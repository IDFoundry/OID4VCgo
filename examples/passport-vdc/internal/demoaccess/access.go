package demoaccess

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// AccessTokenHeader is the header Cloudflare Access sends the origin
// each request's token in.
const AccessTokenHeader = "Cf-Access-Jwt-Assertion" // #nosec G101 -- a header name, not a credential

const (
	// keysLifetime is how long fetched signing keys are used before
	// they're fetched again; keysRefetchAfter how soon after a fetch a
	// token naming an unknown key may fetch them again.
	keysLifetime     = time.Hour
	keysRefetchAfter = time.Minute
	// keysFetchTimeout bounds one fetch of the keys. A fetch runs
	// detached from the request that started it, so a client hanging
	// up can't cut it short.
	keysFetchTimeout = 10 * time.Second
	// maxKeysBytes bounds the certs document read.
	maxKeysBytes = 64 << 10
	// clockSkew is the leeway on exp and nbf.
	clockSkew = time.Minute
)

// AccessVerifier verifies Cloudflare Access application tokens
// (https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/):
// RS256 JWTs signed with one of the team's keys, published at
// https://<team domain>/cdn-cgi/access/certs, whose iss is
// https://<team domain> and whose aud names the application's
// Application Audience (AUD) tag.
type AccessVerifier struct {
	issuer   string
	audience string
	certsURL string
	client   *http.Client
	now      func() time.Time

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time  // the last fetch that succeeded
	failed  time.Time  // the last fetch that failed, zero once one succeeds
	fetch   *keysFetch // the fetch in flight, if any
}

// keysFetch is one fetch of the keys, shared by every request waiting
// on it: err is set before done is closed.
type keysFetch struct {
	done chan struct{}
	err  error
}

// NewAccessVerifier returns a verifier for teamDomain's tokens
// ("example.cloudflareaccess.com") for the application with the AUD tag
// audience, fetching its keys with client (nil: a client with a
// 10-second timeout). Both teamDomain and audience are required.
func NewAccessVerifier(teamDomain, audience string, client *http.Client) (*AccessVerifier, error) {
	teamDomain = strings.TrimSuffix(strings.TrimPrefix(teamDomain, "https://"), "/")
	if teamDomain == "" || audience == "" || strings.ContainsAny(teamDomain, "/?#@") {
		return nil, errors.New("demoaccess: a Cloudflare Access team domain (example.cloudflareaccess.com) and application audience tag are both required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	issuer := "https://" + teamDomain
	return &AccessVerifier{
		issuer: issuer, audience: audience, certsURL: issuer + "/cdn-cgi/access/certs",
		client: client, now: time.Now,
	}, nil
}

// Settings name the Cloudflare Access application guarding the pages:
// its team domain and Application Audience (AUD) tag. The zero
// Settings configure none, for local runs.
type Settings struct {
	TeamDomain string
	Audience   string
}

// RegisterFlags registers -cf-access-team-domain and -cf-access-aud on
// fs, returning the Settings they set once fs is parsed.
func RegisterFlags(fs *flag.FlagSet) *Settings {
	s := &Settings{}
	fs.StringVar(&s.TeamDomain, "cf-access-team-domain", "", "with -cf-access-aud: the Cloudflare Access team domain (example.cloudflareaccess.com) guarding the pages under /demo/; each request for one must then carry a valid Cf-Access-Jwt-Assertion (default: none, for a local run)")
	fs.StringVar(&s.Audience, "cf-access-aud", "", "with -cf-access-team-domain: the Access application's Application Audience (AUD) tag")
	return s
}

// Verifier is the AccessVerifier for s, nil for the zero Settings; an
// error if only one is set. It starts fetching the team's keys at once
// (Prefetch), so the first request needn't wait for them.
func (s Settings) Verifier() (*AccessVerifier, error) {
	if s == (Settings{}) {
		return nil, nil
	}
	v, err := NewAccessVerifier(s.TeamDomain, s.Audience, nil)
	if err != nil {
		return nil, err
	}
	v.Prefetch()
	return v, nil
}

// Prefetch starts fetching the team's keys in the background, unless a
// fetch is already in flight; a failure is logged.
func (v *AccessVerifier) Prefetch() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.startFetch(context.Background())
}

// accessClaims are the claims Verify checks.
type accessClaims struct {
	Issuer    string   `json:"iss"`
	Audience  audience `json:"aud"`
	ExpiresAt *int64   `json:"exp"`
	NotBefore *int64   `json:"nbf"`
}

// audience is aud: a string or an array of them.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// Verify checks token is an RS256 JWT signed with one of the team's
// keys, issued by the team for v's audience, and unexpired.
func (v *AccessVerifier) Verify(ctx context.Context, token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("demoaccess: no Access token")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return fmt.Errorf("demoaccess: token header: %w", err)
	}
	if header.Alg != "RS256" || header.Kid == "" {
		return errors.New("demoaccess: token isn't RS256 with a kid")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return errors.New("demoaccess: token signature isn't base64url")
	}
	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return err
	}
	// RS256 is the algorithm Access signs with; x509 checks it with the
	// key alone.
	signer := &x509.Certificate{PublicKey: key}
	if err := signer.CheckSignature(x509.SHA256WithRSA, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return errors.New("demoaccess: token signature doesn't verify")
	}
	var claims accessClaims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return fmt.Errorf("demoaccess: token claims: %w", err)
	}
	return v.checkClaims(claims)
}

// checkClaims checks the verified claims' issuer, audience and
// validity period.
func (v *AccessVerifier) checkClaims(c accessClaims) error {
	now := v.now()
	switch {
	case c.Issuer != v.issuer:
		return errors.New("demoaccess: token from another issuer")
	case !slices.Contains(c.Audience, v.audience):
		return errors.New("demoaccess: token for another application")
	case c.ExpiresAt == nil || !now.Before(time.Unix(*c.ExpiresAt, 0).Add(clockSkew)):
		return errors.New("demoaccess: token expired")
	case c.NotBefore != nil && now.Add(clockSkew).Before(time.Unix(*c.NotBefore, 0)):
		return errors.New("demoaccess: token not yet valid")
	}
	return nil
}

func decodeSegment(seg string, into any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

// key is the team's signing key kid. The keys are fetched when they're
// stale, or when kid is unknown and they weren't fetched in the last
// keysRefetchAfter; after a failed fetch, none is tried again for
// keysRefetchAfter, and the keys fetched before stay in use. One fetch
// runs at a time, detached from ctx (with a timeout of its own) and
// without holding v.mu: a request that gives up waiting, its client
// gone, leaves it to finish for the requests after it.
func (v *AccessVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	now := v.now()
	k, held := v.keys[kid]
	fresh := !v.fetched.IsZero() && now.Sub(v.fetched) < keysLifetime
	if held && fresh {
		v.mu.Unlock()
		return k, nil
	}
	backingOff := !v.failed.IsZero() && now.Sub(v.failed) < keysRefetchAfter
	if backingOff || (fresh && now.Sub(v.fetched) < keysRefetchAfter) {
		v.mu.Unlock()
		return knownKey(k, held)
	}
	f := v.startFetch(ctx)
	v.mu.Unlock()

	select {
	case <-f.done:
	case <-ctx.Done():
		return nil, fmt.Errorf("demoaccess: waiting for the Access signing keys: %w", ctx.Err())
	}
	v.mu.Lock()
	k, held = v.keys[kid]
	v.mu.Unlock()
	if !held && f.err != nil {
		return nil, f.err
	}
	return knownKey(k, held)
}

func knownKey(k *rsa.PublicKey, held bool) (*rsa.PublicKey, error) {
	if !held {
		return nil, errors.New("demoaccess: token signed with an unknown key")
	}
	return k, nil
}

// startFetch is the fetch of the keys in flight, starting one if there
// is none. v.mu must be held.
func (v *AccessVerifier) startFetch(ctx context.Context) *keysFetch {
	if v.fetch != nil {
		return v.fetch
	}
	f := &keysFetch{done: make(chan struct{})}
	v.fetch = f
	go func() {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), keysFetchTimeout)
		keys, err := v.fetchKeys(fctx)
		cancel()
		v.mu.Lock()
		if err != nil {
			v.failed = v.now()
			log.Printf("demoaccess: %v (not retried for %v)", err, keysRefetchAfter)
		} else {
			v.keys, v.fetched, v.failed = keys, v.now(), time.Time{}
		}
		v.fetch, f.err = nil, err
		v.mu.Unlock()
		close(f.done)
	}()
	return f
}

// fetchKeys fetches the team's RSA signing keys, by kid.
func (v *AccessVerifier) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.certsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("demoaccess: %w", err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("demoaccess: fetch the Access signing keys: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("demoaccess: fetch the Access signing keys: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxKeysBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("demoaccess: the Access signing keys: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		if pub, err := rsaKey(k.N, k.E); err == nil {
			keys[k.Kid] = pub
		}
	}
	return keys, nil
}

// rsaKey is the RSA public key with the base64url modulus n and
// exponent e, of at least 2048 bits.
func rsaKey(n, e string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil || len(eb) == 0 || len(eb) > 4 {
		return nil, errors.New("demoaccess: bad RSA exponent")
	}
	exp := int(new(big.Int).SetBytes(eb).Int64())
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: exp}
	if pub.N.BitLen() < 2048 || exp < 3 || exp%2 == 0 {
		return nil, errors.New("demoaccess: weak RSA key")
	}
	return pub, nil
}
