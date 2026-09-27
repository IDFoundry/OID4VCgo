package verifierapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// maxStatusListBytes bounds a fetched Status List Token.
const maxStatusListBytes = 1 << 20

// checkStatus checks a verified credential against the Token Status List
// it references (draft-14 §8.3): the token's signing certificate must
// chain to a trusted issuer CA (HAIP 1.0 §6.1: the key is in its x5c),
// and the credential's entry must be VALID. A revoked or suspended
// credential, or one whose status can't be established, is an error —
// §8.3: "the Referenced Token SHOULD be rejected".
func (a *App) checkStatus(ctx context.Context, vc verifier.VerifiedCredential) (string, error) {
	ref, cwt, ok, err := statusRef(vc)
	if err != nil {
		return "", fmt.Errorf("the credential's status reference is malformed: %w", err)
	}
	if !ok {
		return "no status reference", nil
	}
	token, err := a.fetchStatusList(ctx, ref.URI, cwt)
	if err != nil {
		return "", fmt.Errorf("couldn't fetch the credential's status list: %w", err)
	}
	opts := statuslist.VerifyOptions{Now: a.now}
	var status statuslist.StatusType
	if cwt {
		status, _, err = statuslist.CheckCWTX5Chain(token, a.issuerRoots, ref, opts)
	} else {
		status, _, err = statuslist.CheckX5C(string(token), a.issuerRoots, ref, opts)
	}
	if err != nil {
		return "", fmt.Errorf("couldn't check the credential's status: %w", err)
	}
	switch status {
	case statuslist.StatusValid:
		return "valid", nil
	case statuslist.StatusInvalid:
		return "", errors.New("the credential has been revoked by its issuer")
	case statuslist.StatusSuspended:
		return "", errors.New("the credential is suspended by its issuer")
	default:
		return "", fmt.Errorf("the credential has status %s, which this verifier doesn't accept", status)
	}
}

// statusRef extracts vc's status list reference: an SD-JWT VC's "status"
// claim (whose Status List Token is a JWT), or an mdoc's MSO status (a
// CWT). ok is false for a credential without one.
func statusRef(vc verifier.VerifiedCredential) (ref statuslist.StatusListRef, cwt, ok bool, err error) {
	if vc.MdocStatus != nil {
		if vc.MdocStatus.StatusList == nil {
			return statuslist.StatusListRef{}, false, false, nil
		}
		sl := vc.MdocStatus.StatusList
		if sl.Idx > uint64(^uint(0)>>1) {
			return statuslist.StatusListRef{}, false, false, errors.New("status list index out of range")
		}
		return statuslist.StatusListRef{Idx: int(sl.Idx), URI: sl.URI}, true, true, nil
	}
	status, present := vc.Claims["status"].(map[string]any)
	if !present {
		return statuslist.StatusListRef{}, false, false, nil
	}
	ref, err = statuslist.ParseStatusClaim(status)
	return ref, false, err == nil, err
}

// fetchStatusList GETs the Status List Token at uri (draft-14 §8.1),
// asking for the format the credential's reference implies.
func (a *App) fetchStatusList(ctx context.Context, uri string, cwt bool) ([]byte, error) {
	if u, err := url.Parse(uri); err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("status list URI %q isn't https", uri)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	accept := statuslist.TokenMediaType
	if cwt {
		accept = statuslist.CWTTokenMediaType
	}
	req.Header.Set("Accept", accept)
	client := a.cfg.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != accept {
		return nil, fmt.Errorf("content type %q, want %q", got, accept)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxStatusListBytes {
		return nil, fmt.Errorf("status list exceeds %d bytes", maxStatusListBytes)
	}
	return body, nil
}
