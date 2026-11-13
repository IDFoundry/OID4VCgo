package main

// The wallet's negative presentations to Verifier2 (-tamper): the
// presentation walletflow builds, changed on its way to Verifier2 as
// the case asks, so that Verifier2 receives what a correct Verifier
// must refuse. Nothing here is in walletflow: the transport stands
// between the wallet and Verifier2, as an attacker relaying a
// presentation would.
//
// The response is encrypted to Verifier2 (direct_post.jwt), so the
// transport first gives the wallet a key of its own to encrypt to: it
// replaces the request object's client_metadata.jwks with that key,
// keeping its kid, and signs the request again with Verifier2's own
// key and x5c (setup's verifier2-key.pem), so the wallet's checks of
// the request still pass. It then decrypts the wallet's response,
// changes the presentation, and encrypts it again to Verifier2's own
// key, as the wallet would have. An SD-JWT VC's Key Binding JWT doesn't
// cover the response encryption key, so the "relay" mode, which
// changes nothing else, shows Verifier2 accepts a relayed presentation;
// each other mode differs from it in one change:
//
//	relay       nothing
//	nonce       the KB-JWT's nonce, signed again with the holder's key
//	aud         the KB-JWT's aud, another x509_hash, signed again
//	disclosure  a disclosure's value, the KB-JWT's sd_hash recomputed
//	            over it and signed again: only the Issuer's digest of
//	            the disclosure no longer matches
//	issuer      the Issuer-signed JWT signed again by a self-signed
//	            certificate nobody was told of, sd_hash recomputed and
//	            the KB-JWT signed again
//
// The holder's key is the wallet's own, from its key store
// (keyring), found by the credential's cnf.jwk.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// tamperModes are -tamper's values.
var tamperModes = []string{"relay", "nonce", "aud", "disclosure", "issuer"}

// maxResponseForm bounds the wallet's direct_post.jwt body.
const maxResponseForm = 1 << 20

// reply is Verifier2's answer to the changed response.
type reply struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// tamperer is the http.RoundTripper that changes the presentation.
type tamperer struct {
	next   http.RoundTripper
	mode   string
	signer *ecdsa.PrivateKey // Verifier2's request object key
	keys   *keyring

	mu          sync.Mutex
	relayKey    *ecdsa.PrivateKey
	verifierKey *ecdsa.PublicKey
	verifierKid string
	responseURI string
	changed     string
	reply       *reply
}

func newTamperer(next http.RoundTripper, mode, signerFile string, keys *keyring) (*tamperer, error) {
	raw, err := os.ReadFile(signerFile) // #nosec G304 -- the operator's own file
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM key", signerFile)
	}
	signer, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	relayKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &tamperer{next: next, mode: mode, signer: signer, keys: keys, relayKey: relayKey}, nil
}

func (t *tamperer) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	responseURI := t.responseURI
	t.mu.Unlock()
	if req.Method == http.MethodPost && responseURI != "" && req.URL.String() == responseURI {
		return t.relayResponse(req)
	}
	res, err := t.next.RoundTrip(req)
	if err != nil || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/oauth-authz-req+jwt") {
		return res, err
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		return nil, err
	}
	changed, err := t.rewriteRequest(string(body))
	if err != nil {
		return nil, fmt.Errorf("tamper: request object: %w", err)
	}
	res.Body = io.NopCloser(strings.NewReader(changed))
	res.ContentLength = int64(len(changed))
	res.Header.Set("Content-Length", strconv.Itoa(len(changed)))
	return res, nil
}

// outcome is what the tamperer changed and how Verifier2 answered.
func (t *tamperer) outcome() *tampered {
	t.mu.Lock()
	defer t.mu.Unlock()
	return &tampered{Mode: t.mode, Changed: t.changed, Reply: t.reply}
}

// rewriteRequest replaces the request object's response encryption key
// with the relay's, keeping its kid, and signs it again with
// Verifier2's key, keeping its header (x5c, typ).
func (t *tamperer) rewriteRequest(compact string) (string, error) {
	header, payload, err := jose.DecodeUnverifiedMax(compact, maxRecordedBody)
	if err != nil {
		return "", err
	}
	claims, err := decodeObject(payload)
	if err != nil {
		return "", err
	}
	meta, _ := claims["client_metadata"].(map[string]any)
	set, _ := meta["jwks"].(map[string]any)
	keys, _ := set["keys"].([]any)
	if len(keys) != 1 {
		return "", fmt.Errorf("client_metadata.jwks has %d keys, want one", len(keys))
	}
	original, _ := keys[0].(map[string]any)
	pub, err := publicKey(original)
	if err != nil {
		return "", fmt.Errorf("client_metadata.jwks: %w", err)
	}
	responseURI, _ := claims["response_uri"].(string)
	if responseURI == "" {
		return "", errors.New("no response_uri")
	}
	relay, err := jwk.Marshal(&t.relayKey.PublicKey)
	if err != nil {
		return "", err
	}
	replacement := map[string]any{}
	for k, v := range original {
		replacement[k] = v
	}
	replacement["x"], replacement["y"] = relay.X, relay.Y
	set["keys"] = []any{replacement}

	t.mu.Lock()
	t.verifierKey = pub
	t.verifierKid, _ = original["kid"].(string)
	t.responseURI = responseURI
	t.mu.Unlock()

	out, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	delete(header, "alg")
	return jose.Sign(jose.ES256, t.signer, header, out)
}

// relayResponse decrypts the wallet's direct_post.jwt response, changes
// its presentation, encrypts it again to Verifier2 and posts it on,
// recording Verifier2's answer.
func (t *tamperer) relayResponse(req *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(io.LimitReader(req.Body, maxResponseForm+1))
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(raw) > maxResponseForm {
		return nil, fmt.Errorf("tamper: the response exceeds %d bytes", maxResponseForm)
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		return nil, err
	}
	header, err := jwe.DecodeHeader(form.Get("response"))
	if err != nil {
		return nil, fmt.Errorf("tamper: response: %w", err)
	}
	enc, _ := header["enc"].(string)
	plain, err := jwe.Decrypt(t.relayKey, form.Get("response"))
	if err != nil {
		return nil, fmt.Errorf("tamper: decrypt the response: %w", err)
	}
	body, err := decodeObject(plain)
	if err != nil {
		return nil, err
	}
	tokens, _ := body["vp_token"].(map[string]any)
	if len(tokens) != 1 {
		return nil, fmt.Errorf("tamper: vp_token has %d entries, want one", len(tokens))
	}
	for id, v := range tokens {
		list, _ := v.([]any)
		if len(list) != 1 {
			return nil, fmt.Errorf("tamper: vp_token %s has %d presentations, want one", id, len(list))
		}
		presentation, _ := list[0].(string)
		changed, what, err := t.change(presentation)
		if err != nil {
			return nil, fmt.Errorf("tamper: %s: %w", t.mode, err)
		}
		list[0] = changed
		t.mu.Lock()
		t.changed = what
		t.mu.Unlock()
	}
	out, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	pub, kid := t.verifierKey, t.verifierKid
	t.mu.Unlock()
	sealed, err := jwe.Encrypt(pub, jwe.Enc(enc), out, jwe.EncryptOptions{KeyID: kid})
	if err != nil {
		return nil, err
	}
	form.Set("response", sealed)
	encoded := form.Encode()
	forward := req.Clone(req.Context())
	forward.Body = io.NopCloser(strings.NewReader(encoded))
	forward.ContentLength = int64(len(encoded))
	res, err := t.next.RoundTrip(forward)
	if err != nil {
		return nil, err
	}
	answer, err := io.ReadAll(io.LimitReader(res.Body, maxRecordedBody+1))
	_ = res.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(answer) > maxRecordedBody {
		return nil, fmt.Errorf("tamper: Verifier2's answer exceeds %d bytes", maxRecordedBody)
	}
	t.mu.Lock()
	t.reply = &reply{Status: res.StatusCode, Body: string(answer)}
	t.mu.Unlock()
	res.Body = io.NopCloser(bytes.NewReader(answer))
	return res, nil
}

// change is presentation, an SD-JWT VC with a Key Binding JWT, changed
// as the mode says, and what was changed.
func (t *tamperer) change(presentation string) (string, string, error) {
	parts := strings.Split(presentation, "~")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		return "", "", errors.New("not an SD-JWT with a Key Binding JWT")
	}
	issuerJWT, disclosures, kb := parts[0], parts[1:len(parts)-1], parts[len(parts)-1]
	kbHeader, kbPayload, err := jose.DecodeUnverifiedMax(kb, maxRecordedBody)
	if err != nil {
		return "", "", fmt.Errorf("KB-JWT: %w", err)
	}
	kbClaims, err := decodeObject(kbPayload)
	if err != nil {
		return "", "", err
	}
	var what string
	switch t.mode {
	case "relay":
		return presentation, "nothing", nil
	case "nonce":
		kbClaims["nonce"] = "not-" + fmt.Sprint(kbClaims["nonce"])
		what = "KB-JWT nonce " + fmt.Sprint(kbClaims["nonce"])
	case "aud":
		other := sha256.Sum256([]byte("another Verifier's Access Certificate"))
		kbClaims["aud"] = "x509_hash:" + base64.RawURLEncoding.EncodeToString(other[:])
		what = "KB-JWT aud " + fmt.Sprint(kbClaims["aud"])
	case "disclosure":
		if len(disclosures) == 0 {
			return "", "", errors.New("the presentation has no disclosure to change")
		}
		changed, name, err := changeDisclosure(disclosures[0])
		if err != nil {
			return "", "", err
		}
		disclosures[0] = changed
		what = "disclosure " + name + "'s value"
	case "issuer":
		resigned, err := selfSigned(issuerJWT)
		if err != nil {
			return "", "", err
		}
		issuerJWT = resigned
		what = "Issuer-signed JWT signed by a self-signed certificate"
	default:
		return "", "", fmt.Errorf("unknown mode %q", t.mode)
	}
	sdJWT := issuerJWT + "~" + strings.Join(disclosures, "~") + "~"
	if len(disclosures) == 0 {
		sdJWT = issuerJWT + "~"
	}
	sum := sha256.Sum256([]byte(sdJWT))
	kbClaims["sd_hash"] = base64.RawURLEncoding.EncodeToString(sum[:])
	holder, err := t.keys.holderOf(parts[0])
	if err != nil {
		return "", "", err
	}
	out, err := json.Marshal(kbClaims)
	if err != nil {
		return "", "", err
	}
	delete(kbHeader, "alg")
	signed, err := jose.Sign(jose.ES256, holder, kbHeader, out)
	if err != nil {
		return "", "", err
	}
	return sdJWT + signed, what, nil
}

// changeDisclosure is a disclosure, [salt, name, value], with its value
// changed, and the claim's name.
func changeDisclosure(d string) (string, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil {
		return "", "", err
	}
	var parts []any
	if err := json.Unmarshal(raw, &parts); err != nil || len(parts) != 3 {
		return "", "", errors.New("the disclosure isn't [salt, name, value]")
	}
	name, _ := parts[1].(string)
	if s, ok := parts[2].(string); ok && s != "1900-01-01" {
		parts[2] = "1900-01-01"
	} else {
		parts[2] = "1901-01-01"
	}
	out, err := json.Marshal(parts)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(out), name, nil
}

// selfSigned is the Issuer-signed JWT signed again by a fresh key, with
// a self-signed certificate for it as its x5c.
func selfSigned(compact string) (string, error) {
	header, payload, err := jose.DecodeUnverifiedMax(compact, maxRecordedBody)
	if err != nil {
		return "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "An issuer nobody trusts", Country: []string{"AT"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	header["x5c"] = []string{base64.StdEncoding.EncodeToString(der)}
	delete(header, "alg")
	return jose.Sign(jose.ES256, key, header, payload)
}

// publicKey is an EC P-256 JWK's public key, whatever other members it
// has.
func publicKey(k map[string]any) (*ecdsa.PublicKey, error) {
	raw, err := json.Marshal(map[string]any{"kty": k["kty"], "crv": k["crv"], "x": k["x"], "y": k["y"]})
	if err != nil {
		return nil, err
	}
	pub, err := jwk.ParsePublicKey(raw)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("not an EC P-256 key")
	}
	return ec, nil
}

// decodeObject is a JSON object, its numbers kept as written.
func decodeObject(raw []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// keyring is the wallet's key store, remembering each key it hands out,
// so the transport can sign as the holder.
type keyring struct {
	walletflow.KeyStore

	mu   sync.Mutex
	keys []walletflow.Key
}

func (k *keyring) remember(key walletflow.Key, err error) (walletflow.Key, error) {
	if err == nil {
		k.mu.Lock()
		k.keys = append(k.keys, key)
		k.mu.Unlock()
	}
	return key, err
}

func (k *keyring) NewKey(ctx context.Context, purpose walletflow.KeyPurpose) (walletflow.Key, error) {
	return k.remember(k.KeyStore.NewKey(ctx, purpose))
}

func (k *keyring) Key(ctx context.Context, id string) (walletflow.Key, error) {
	return k.remember(k.KeyStore.Key(ctx, id))
}

// holderOf is the key an Issuer-signed JWT's cnf.jwk names.
func (k *keyring) holderOf(issuerJWT string) (crypto.Signer, error) {
	_, payload, err := jose.DecodeUnverifiedMax(issuerJWT, maxRecordedBody)
	if err != nil {
		return nil, err
	}
	var claims struct {
		Cnf struct {
			JWK map[string]any `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Cnf.JWK == nil {
		return nil, errors.New("the credential has no cnf.jwk")
	}
	pub, err := publicKey(claims.Cnf.JWK)
	if err != nil {
		return nil, fmt.Errorf("cnf.jwk: %w", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, key := range k.keys {
		if p, ok := key.Public().(*ecdsa.PublicKey); ok && p.Equal(pub) {
			return key, nil
		}
	}
	return nil, errors.New("no key of the wallet's is the credential's cnf.jwk")
}
