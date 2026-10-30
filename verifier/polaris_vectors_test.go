package verifier

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// Polaris negative vectors for SD-JWT VC presentations under OpenID4VP 1.0
// and HAIP 1.0: github.com/EgorKhaklin/polaris-id,
// lab/interop/negative-vectors. vectors.json holds valid presentations (the
// controls, which every verifier must accept) and presentations that each
// differ from a control in one thing a verifier must refuse, with the
// clauses that say so. This test feeds each one to VerifyResponse and, for
// the vectors that name a Token Status List, to RequireValidStatus, and
// compares the verdict with the file's.
//
// The file isn't vendored. The Polaris vectors workflow checks polaris-id
// out at a pinned commit and sets POLARIS_VECTORS to the file; without it
// this test is skipped, so a plain `go test ./...` needs no network. The
// file's SHA-256 is pinned too, so the checkout can't change under the test.
//
// To move the pin: read what changed in the vectors since the commit below,
// then set both constants and the ref of the vectors job in
// .github/workflows/polaris-vectors.yml to the new commit. The hash is
// sha256sum lab/interop/negative-vectors/vectors.json in that checkout.
const (
	polarisVectorsCommit = "675c59ac4c6a2679d8c624eb782583159bc6d2ee"
	polarisVectorsSHA256 = "c3b0effe6a74f5e07f66ffc704fba940f5703635d94fa04d3b47ac504484f76e"
)

// polarisLayersNotImplemented are the vector layers this package leaves to
// its caller, with why: the vectors in them are reported as skipped, not as
// passes. Every layer in the file applies to a verifier that resolves
// issuer keys from x5c and can check a Token Status List, so it is empty.
var polarisLayersNotImplemented = map[string]string{}

// polarisKnownGaps are the refusals this package does not make at the pinned
// commit, by vector id, with the layer and the clause each rests on. A listed
// vector that is accepted is logged as a known gap and does not fail the
// test. A listed vector that is now refused fails the test: remove it from
// this map. Any other vector with a wrong verdict fails the test, and so does
// a refused control. Controls are never listed.
var polarisKnownGaps = map[string]polarisGap{}

// polarisRequireIssuerName are the vectors judged with
// X5CIssuerKeyResolver.RequireIssuerName set, by id. They test a relying
// party's policy: SD-JWT VC doesn't require a credential's iss to name the
// x5c leaf (oauth-wg/oauth-sd-jwt-vc#436), though the corpus at 0.3.0 still
// grades them spec-implied. The check is off by default, so these three are
// refused only when the caller opts in. Every other vector is judged on the
// package's defaults.
var polarisRequireIssuerName = map[string]bool{
	"x5c-leaf-names-other-issuer": true,
	"x5c-leaf-names-other-host":   true,
	"x5c-leaf-uri-beats-host":     true,
}

type polarisGap struct{ layer, clause, note string }

type polarisFile struct {
	Version  string          `json:"version"`
	Settings polarisSettings `json:"settings"`
	Vectors  []polarisVector `json:"vectors"`
}

type polarisSettings struct {
	Now             int64             `json:"now"`
	Nonce           string            `json:"nonce"`
	Audience        string            `json:"audience"`
	VCT             string            `json:"vct"`
	MaxSkewSeconds  int64             `json:"max_skew_seconds"`
	TrustAnchorsPEM []string          `json:"trust_anchors_pem"`
	IssuerJWKs      []json.RawMessage `json:"issuer_jwks"`
}

type polarisVector struct {
	ID           string `json:"id"`
	Layer        string `json:"layer"`
	Class        string `json:"class"`
	Expected     string `json:"expected"`
	Trust        string `json:"trust"`
	Presentation string `json:"presentation"`
	Clauses      []struct {
		Ref string `json:"ref"`
	} `json:"clauses"`
	// StatusList is what a GET of the status list uri the credential names
	// returns; a nil Response is no answer.
	StatusList *struct {
		URI      string  `json:"uri"`
		Response *string `json:"response"`
	} `json:"status_list"`
}

// polarisFixedKey resolves every issuer JWT to one key, for the vectors
// whose issuer key is given as a JWK rather than in x5c.
type polarisFixedKey struct{ pub crypto.PublicKey }

func (r polarisFixedKey) ResolveIssuerKey(context.Context, map[string]any, map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	alg, err := sdjwtvcAlgForKey(r.pub)
	return r.pub, alg, err
}

// Capabilities declares LiveFetchHardened only so that AssuranceProduction,
// which this test runs under, accepts a fixed key. polarisFixedKey fetches
// nothing; the declaration is no claim about any key source outside this
// test.
func (polarisFixedKey) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: true}
}

// polarisServe is an http.RoundTripper that answers one uri with a body
// from memory, and anything else with no answer. It opens no socket.
type polarisServe struct {
	uri  string
	body *string
}

func (s polarisServe) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != s.uri || s.body == nil {
		return nil, fmt.Errorf("no answer from %s", req.URL)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {statuslist.TokenMediaType}},
		Body:       io.NopCloser(strings.NewReader(*s.body)),
		Request:    req,
	}, nil
}

// TestPolarisNegativeVectors: see the comment above polarisVectorsCommit.
// The controls run first, and the test stops if any is refused: refusals
// measured with a verifier that refuses everything mean nothing.
func TestPolarisNegativeVectors(t *testing.T) {
	path := os.Getenv("POLARIS_VECTORS")
	if path == "" {
		t.Skip("POLARIS_VECTORS is not set: the Polaris vectors workflow sets it to vectors.json at polaris-id " + polarisVectorsCommit)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != polarisVectorsSHA256 {
		t.Fatalf("vectors.json has SHA-256 %x, want %s (polaris-id %s)", sum, polarisVectorsSHA256, polarisVectorsCommit)
	}
	var file polarisFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}

	roots := x509.NewCertPool()
	for _, p := range file.Settings.TrustAnchorsPEM {
		if !roots.AppendCertsFromPEM([]byte(p)) {
			t.Fatal("settings.trust_anchors_pem holds no certificate")
		}
	}
	if len(file.Settings.IssuerJWKs) == 0 {
		t.Fatal("settings.issuer_jwks is empty")
	}
	issuerPub, err := jwk.ParsePublicKey(file.Settings.IssuerJWKs[0])
	if err != nil {
		t.Fatalf("settings.issuer_jwks[0]: %v", err)
	}
	run := polarisRun{settings: file.Settings, roots: roots, issuerPub: issuerPub}

	var controls, refusals []polarisVector
	for _, v := range file.Vectors {
		if v.Class == "control" {
			controls = append(controls, v)
		} else {
			refusals = append(refusals, v)
		}
	}
	if len(controls) == 0 || len(refusals) == 0 {
		t.Fatalf("the file holds %d controls and %d refusals: it measures nothing", len(controls), len(refusals))
	}

	for id := range polarisKnownGaps {
		if !slices.ContainsFunc(refusals, func(v polarisVector) bool { return v.ID == id }) {
			t.Errorf("known gap %q is not a refusal in this file: remove it from polarisKnownGaps", id)
		}
	}
	for id := range polarisRequireIssuerName {
		if !slices.ContainsFunc(refusals, func(v polarisVector) bool { return v.ID == id && v.Trust == "x5c" }) {
			t.Errorf("%q in polarisRequireIssuerName is not an x5c refusal in this file", id)
		}
	}

	var passed, gaps, failed, skipped int
	for _, group := range [][]polarisVector{controls, refusals} {
		for _, v := range group {
			ok := t.Run(v.ID, func(t *testing.T) {
				if why, notImplemented := polarisLayersNotImplemented[v.Layer]; notImplemented {
					skipped++
					t.Skipf("skipped by layer %s: %s", v.Layer, why)
				}
				got, why := run.judge(t, v)
				gap, listed := polarisKnownGaps[v.ID]
				switch {
				case got == v.Expected && listed:
					failed++
					t.Errorf("fail: %s is now %sed, as the file says, but is in polarisKnownGaps: remove it from the map", v.ID, got)
				case got == v.Expected:
					passed++
					t.Logf("pass: %s (%s)", got, why)
				case listed:
					gaps++
					t.Logf("known gap: %s, layer %s, %s: judged %q, file says %q (%s)", v.ID, gap.layer, gap.clause, got, v.Expected, gap.note)
				default:
					failed++
					refs := make([]string, len(v.Clauses))
					for i, c := range v.Clauses {
						refs[i] = c.Ref
					}
					t.Errorf("fail: %s, layer %s, %s: judged %q, want %q (%s)", v.ID, v.Layer, strings.Join(refs, "; "), got, v.Expected, why)
				}
			})
			if !ok && v.Class == "control" {
				t.Fatalf("control %s was refused: the refusals measure nothing", v.ID)
			}
		}
	}
	t.Logf("vectors %s, polaris-id %s: %d pass, %d known gaps, %d fail, %d skipped by layer",
		file.Version, polarisVectorsCommit, passed, gaps, failed, skipped)
}

type polarisRun struct {
	settings  polarisSettings
	roots     *x509.CertPool
	issuerPub crypto.PublicKey
}

// judge gives one vector to the package and returns "accept" or "reject"
// and why. An error that isn't the package refusing the presentation (a
// mistake in this test's own setup) fails the test.
func (r polarisRun) judge(t *testing.T, v polarisVector) (verdict, why string) {
	t.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{r.settings.VCT}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	const queryID = "pid"
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: queryID, Format: sdjwtvc.CredentialFormat, Meta: meta}}}

	var keys SDJWTVCIssuerKeyResolver
	switch v.Trust {
	case "x5c":
		keys = X5CIssuerKeyResolver{Roots: r.roots, RequireIssuerName: polarisRequireIssuerName[v.ID], Revocation: certrevocation.NoCheck{}}
	case "jwks":
		keys = polarisFixedKey{pub: r.issuerPub}
	default:
		t.Fatalf("vector trust %q is not one this test knows", v.Trust)
	}
	// The vectors' Client Identifier is a fixed string, not one derived from
	// a certificate this test holds, so the Verifier is built from its parts
	// rather than through New: cfg and clientID are set here, and deps is
	// left zero, since its Signer and Random serve requests, which this test
	// never builds. If Verifier gains a field, set it here too or leave it
	// zero on purpose.
	verifier := &Verifier{cfg: Config{Assurance: AssuranceProduction}, clientID: r.settings.Audience}
	skew := time.Duration(r.settings.MaxSkewSeconds) * time.Second
	now := func() time.Time { return time.Unix(r.settings.Now, 0) }

	result, err := verifier.VerifyResponse(context.Background(), VerifyResponseRequest{
		Query:            query,
		Response:         ParsedResponse{VPToken: map[string][]string{queryID: {v.Presentation}}},
		ExpectedNonce:    r.settings.Nonce,
		IssuerKeys:       keys,
		Now:              now,
		MaxClockSkew:     skew,
		MaxKeyBindingAge: skew,
		// The vectors pin no issuer per type, and test no status: the
		// production decisions are declared, not made.
		AnyIssuerForAnyType: true,
		NoStatusCheck:       true,
		// The vectors' requests name no claims, yet their presentations
		// disclose some (OpenID4VP 1.0 §6.4.1 would have a Wallet disclose
		// none): they test the presentation's verification, not its fit
		// to the query, so unrequested claims are let through.
		AllowUnrequestedClaims: true,
	})
	if err != nil {
		var refused *Error
		if !errors.As(err, &refused) {
			t.Fatalf("%s: VerifyResponse failed for a reason other than refusing the presentation: %v", v.ID, err)
		}
		return "reject", fmt.Sprintf("%s: %s", refused.Reason(), err)
	}
	if len(result.Credentials) != 1 {
		t.Fatalf("%s: VerifyResponse accepted %d credentials, want 1", v.ID, len(result.Credentials))
	}
	if v.StatusList != nil {
		// A refusal here is the status check's: nothing else in this call can
		// fail, as the roots and the reference are set.
		if err := r.requireValidStatus(t, result.Credentials[0], v, now); err != nil {
			return "reject", "status: " + err.Error()
		}
	}
	return "accept", "verified"
}

// requireValidStatus checks vc's status as a deployment that requires one
// does: with RequireValidStatus, given a statuslist.Checker that gets the
// Status List Token from memory and validates its x5c chain to the trust
// anchors. RequireValidStatus also requires the token signed by vc's issuer.
func (r polarisRun) requireValidStatus(t *testing.T, vc VerifiedCredential, v polarisVector, now func() time.Time) error {
	t.Helper()
	// RequireValidStatus passes a credential with no status reference, so a
	// vector that names a status list must carry one.
	if _, _, ok, err := vc.StatusListRef(); err == nil && !ok {
		t.Fatalf("%s: the credential names no status list", v.ID)
	}
	checker := statuslist.Checker{
		Fetcher: statuslist.Fetcher{
			HTTP:               &http.Client{Transport: polarisServe{uri: v.StatusList.URI, body: v.StatusList.Response}},
			UncheckedTransport: true,
		},
		Roots:   r.roots,
		Options: statuslist.VerifyOptions{Now: now},
	}
	return RequireValidStatus(checker)(context.Background(), v.ID, VerifyResponseResult{Credentials: []VerifiedCredential{vc}})
}
