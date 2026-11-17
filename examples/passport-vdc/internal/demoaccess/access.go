package demoaccess

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
	fetched time.Time
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
// error if only one is set.
func (s Settings) Verifier() (*AccessVerifier, error) {
	if s == (Settings{}) {
		return nil, nil
	}
	return NewAccessVerifier(s.TeamDomain, s.Audience, nil)
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
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
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

// key is the team's signing key kid, fetching the keys if they're
// stale, or if kid is unknown and they weren't fetched (or tried) in
// the last keysRefetchAfter. Should a fetch fail, the keys fetched
// before stay in use.
func (v *AccessVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	since := now.Sub(v.fetched)
	if k, ok := v.keys[kid]; ok && since < keysLifetime {
		return k, nil
	}
	if since >= keysRefetchAfter || v.fetched.IsZero() {
		v.fetched = now
		keys, err := v.fetchKeys(ctx)
		if _, held := v.keys[kid]; err != nil && !held {
			return nil, err
		} else if err == nil {
			v.keys = keys
		}
	}
	k, ok := v.keys[kid]
	if !ok {
		return nil, errors.New("demoaccess: token signed with an unknown key")
	}
	return k, nil
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
