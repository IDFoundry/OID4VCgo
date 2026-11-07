package walletprovider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/androidattest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/statefile"
	"github.com/idfoundry/oid4vcgo/statuslist"
	wp "github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
	"github.com/idfoundry/oid4vcgo/walletprovider/appattest"
)

// The service's paths, relative to its URL: the demo wallets' own
// protocol. The library's (walletprovider.Handler) is served under
// /v1/ beside it.
const (
	WalletAttestationPath = "/wallet-attestation"
	KeyAttestationPath    = "/key-attestation"
	ChallengePath         = "/attestation-challenge"
)

const (
	// WalletAttestationLifetime is how long a Wallet Attestation the
	// service issues is valid.
	WalletAttestationLifetime = wp.DefaultWalletAttestationTTL
	// KeyAttestationLifetime is how long a Key Attestation the service
	// issues is valid. Its c_nonce makes it fresh when it's sent, but
	// its exp is when the keys it attests expire too (OpenID4VCI 1.0
	// Appendix D.1), which the issuer checks again when a review it
	// deferred issuance for is approved: it outlasts that review.
	KeyAttestationLifetime = wp.DefaultKeyAttestationTTL

	// DefaultURL is where cmd/wallet-provider serves the service by
	// default, and so where the status list is when ServiceConfig.URL
	// is empty.
	DefaultURL = "https://127.0.0.1:6443"

	// WalletName is the Wallet Attestations' wallet_name.
	WalletName = "passport-vdc demo wallet"

	// maxRequestBytes fits maxAttestedKeys keys with their attestation
	// chains.
	maxRequestBytes = 256 * 1024
	maxAttestedKeys = wp.DefaultMaxKeys
	maxNonceLength  = 256
)

// WalletAttestationRequest asks the service for a Wallet Attestation
// binding InstanceKey, a public JWK, to ClientID. An Android wallet
// sends the key's Android Key Attestation chain, made over a challenge
// from ChallengePath, as InstanceKeyCertificateChain.
type WalletAttestationRequest struct {
	ClientID    string          `json:"client_id"`
	InstanceKey json.RawMessage `json:"instance_key"`
	// InstanceKeyCertificateChain is the key's certificate chain, each
	// certificate base64 (not base64url) DER, the key's own first, as
	// in x5c.
	InstanceKeyCertificateChain []string `json:"instance_key_certificate_chain,omitempty"`
}

// KeyAttestationRequest asks the service for a Key Attestation over
// Keys, public JWKs, carrying the Credential Issuer's Nonce. An Android
// wallet sends each key's Android Key Attestation chain in
// CertificateChains, in the order of Keys (an empty chain for a key it
// has none for). InstanceKey is the instance key of the issuance the
// keys are for, a public JWK a Wallet Attestation from the service
// recorded: the Key Attestation carries that key's status, so
// suspending or revoking its instance withdraws it too. Without one,
// as an older wallet sends, it's issued under the service's shared
// holder instance.
type KeyAttestationRequest struct {
	InstanceKey       json.RawMessage   `json:"instance_key,omitempty"`
	Keys              []json.RawMessage `json:"keys"`
	Nonce             string            `json:"nonce"`
	CertificateChains [][]string        `json:"certificate_chains,omitempty"`
}

// AttestationResponse is the service's answer to either request.
type AttestationResponse struct {
	Attestation string `json:"attestation"`
}

// ServiceConfig configures the provider's service.
type ServiceConfig struct {
	// ClientID is the demo wallet's registration with the issuer, the
	// only client the service attests.
	ClientID string
	// RequireHardwareKeyAttestation refuses a key whose Android Key
	// Attestation chain is verified but not one Google vouches for: it
	// doesn't end at a Google hardware attestation root, a certificate
	// in it is outside its validity, or it says the key or the
	// attestation is in software (an emulator). Without it they're
	// attested, and logged. A key sent without a chain (from iOS, the
	// CLI or web wallet, or an older app) is attested either way.
	RequireHardwareKeyAttestation bool
	// VerifiedKeysPath is the file that keeps the keys whose chains the
	// service verified, so a key re-attested after a restart is still
	// recognised; empty keeps them in memory only.
	VerifiedKeysPath string
	// AttestationRoots are the roots a hardware chain ends at; nil
	// means Google's hardware attestation roots.
	AttestationRoots []*x509.Certificate
	// URL is the service's public https URL: the library's protocol is
	// served under it at /v1/, and the provider's status lists, which
	// every attestation names, under /v1/status/. Empty means DefaultURL.
	URL string
	// InstancesPath is the file that keeps the library instances the
	// service registers and their instance keys, and StatusIndicesPath
	// the file that keeps the instance keys' status list indices and
	// statuses, so a restart neither forgets an instance key nor hands
	// its index out again; empty keeps each in memory only.
	InstancesPath     string
	StatusIndicesPath string
	// AndroidApps, if set, are the Android apps whose keys the
	// library's own protocol (/v1/) attests, through
	// androidkey.EvidenceVerifier: chains to Google's roots, checked
	// against Google's attestation status list, from a locked device
	// with verified boot, made by one of these apps, signed with every
	// certificate listed. Without it or IOSApps /v1/ attests nothing
	// but the demo-only evidence.
	AndroidApps []androidkey.AllowedApp
	// IOSApps, if set, are the iOS apps — App IDs, team ID and bundle
	// ID, "ABCDE12345.dev.idfoundry.oid4vcgo.demowallet" — whose keys
	// /v1/ attests with App Attest evidence, through
	// appattest.EvidenceVerifier: an App Attest key Apple attested for
	// one of these apps, then its assertions over the keys. Development
	// environment keys are accepted, as a demo build's are; a
	// production provider leaves appattest.Verifier.AllowDevelopment
	// unset. With IOSApps the older protocol's endpoints
	// (ChallengePath, WalletAttestationPath, KeyAttestationPath), which
	// attest any caller, answer 403: App Attest over /v1/ is the only
	// way to an attestation from outside the process. A wallet in the
	// same process still speaks the older protocol through
	// Service.InProcessClient.
	IOSApps []string
	// Logf logs each attestation and what was made of its evidence; nil
	// means log.Printf.
	Logf func(format string, args ...any)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Handler serves the provider for clientID with the defaults of
// ServiceConfig: see NewService.
func (p *Provider) Handler(clientID string) http.Handler {
	h, err := p.NewService(ServiceConfig{ClientID: clientID})
	if err != nil { // only reading VerifiedKeysPath, or a bad ClientID, fails
		panic(err)
	}
	return h
}

// NewService serves the provider as a service the demo wallets call, so
// they never hold its key. The attestations are issued by the library's
// Wallet Provider (oid4vcgo/walletprovider), signed with p's key and
// certificate: each instance key is recorded for an instance of its
// own, every attestation names its instance key's entry in the
// provider's status lists, served under /v1/status/, and the library's
// own protocol is served under /v1/ for a wallet that speaks it (see
// ServiceConfig.AndroidApps).
//
// The demo wallets speak this package's older, stateless protocol:
// POST WalletAttestationPath with a WalletAttestationRequest, or
// KeyAttestationPath with a KeyAttestationRequest, answered with an
// AttestationResponse; POST ChallengePath with a ChallengeRequest for a
// ChallengeResponse.
//
// It attests only cfg.ClientID. A key sent with an Android Key
// Attestation chain is attested only if the chain's signatures hold,
// it certifies that key, and its challenge is one the service issued
// for the key's purpose, unused and unexpired (or the chain is one the
// service verified for this key before); whether it's also hardware
// Google vouches for is logged, and required with
// cfg.RequireHardwareKeyAttestation. A key sent without a chain is
// attested, and logged as such. It doesn't authenticate the wallet
// asking; ChallengePath answers each client address a limited number of
// times a second (429 past it), so one client can't use up the
// challenges every other one needs, and so do the library protocol's
// unauthenticated /v1/challenge and /v1/instances.
//
// The library attests nothing without platform evidence, and the older
// protocol carries none from iOS, the CLI or the web wallet, and names
// no instance. So the service vouches for each request it has checked
// with DEMO-ONLY evidence (DemoEvidenceKind). The first time a Wallet
// Attestation is asked for an instance key, the service registers an
// instance for it, with a registration key of the service's own that
// signs nothing, and records the instance key for that instance at
// the security level its chain showed (software without one). A Key
// Attestation is issued for the instance key the request names, under
// that key's instance, so it carries that key's status (an instance key
// no Wallet Attestation recorded is refused, 400); one naming none, for
// one shared instance key of one shared instance the service registers
// for the purpose. Suspending or
// revoking an instance through the library stops its Wallet
// Attestations and sets its instance key's status. Without
// ServiceConfig's paths, instances and status indices are kept in
// memory: a restart forgets them, and a wallet's instance key is then
// recorded again, as it is once the library's retention has deleted
// its record. Run the service's SweepEvery to delete the status lists
// of the periods no longer served.
func (p *Provider) NewService(cfg ServiceConfig) (*Service, error) {
	s, err := p.newService(cfg)
	if err != nil {
		return nil, err
	}
	return &Service{Handler: s.handler(len(cfg.IOSApps) == 0), s: s}, nil
}

// Service is the provider's service (NewService): an http.Handler.
type Service struct {
	http.Handler
	s *service
}

// InProcessClient is an HTTP client for a wallet in the service's own
// process (cmd/demo's web wallet): it serves each request with the
// service's handler, without a connection, and with the older
// protocol's endpoints even where Handler refuses them
// (ServiceConfig.IOSApps). Its requests come from 127.0.0.1, for the
// rate limits.
func (s *Service) InProcessClient() *http.Client {
	return &http.Client{Transport: handlerTransport{s.s.handler(true)}, Timeout: 10 * time.Second}
}

// handlerTransport is an http.RoundTripper that serves each request
// with h, in process.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	req := r.Clone(r.Context())
	req.RemoteAddr, req.RequestURI = "127.0.0.1:0", r.URL.RequestURI()
	if req.Body == nil {
		req.Body = http.NoBody
	}
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// Sweep deletes the status lists of the periods the library Wallet
// Provider no longer serves (wp.Provider.SweepStatusLists), logging
// what it did. The instance key store drops expired instance keys
// itself, as it records new ones.
func (s *Service) Sweep(ctx context.Context) {
	n, err := s.s.lib.SweepStatusLists(ctx)
	switch {
	case err != nil:
		s.s.cfg.Logf("wallet provider: deleting the status lists of past periods (%d deleted): %v", n, err)
	case n > 0:
		s.s.cfg.Logf("wallet provider: deleted %d status lists of past periods", n)
	}
}

// SweepEvery runs Sweep at once, then every interval until ctx is done.
func (s *Service) SweepEvery(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.Sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// handler serves the library's protocol under /v1/ and, if legacy,
// the older protocol's endpoints; otherwise they answer 403.
func (s *service) handler(legacy bool) http.Handler {
	mux := http.NewServeMux()
	if legacy {
		mux.HandleFunc("POST "+ChallengePath, s.challenge)
		mux.HandleFunc("POST "+WalletAttestationPath, s.walletAttestation)
		mux.HandleFunc("POST "+KeyAttestationPath, s.keyAttestation)
	} else {
		for _, path := range []string{ChallengePath, WalletAttestationPath, KeyAttestationPath} {
			mux.HandleFunc("POST "+path, refuseUnattested)
		}
	}
	v1 := s.lib.Handler()
	mux.Handle("/v1/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path == wp.ChallengePath || r.URL.Path == wp.InstancesPath) && !s.challenges.allow(clientAddress(r), s.cfg.Now()) {
			writeError(w, http.StatusTooManyRequests, "too many requests from this address; try again shortly")
			return
		}
		v1.ServeHTTP(w, r)
	}))
	return mux
}

// refuseUnattested answers a request of the older protocol, which
// attests any caller, when the service attests iOS apps with App
// Attest (ServiceConfig.IOSApps).
func refuseUnattested(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusForbidden, "this Wallet Provider attests only over /v1/, with platform evidence: it was started with -ios-app, which turns off the demo protocol that attests any caller")
}

func (p *Provider) newService(cfg ServiceConfig) (*service, error) {
	if cfg.AttestationRoots == nil {
		cfg.AttestationRoots = androidattest.GoogleRoots()
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.URL == "" {
		cfg.URL = DefaultURL
	}
	ev, err := newEvidence(cfg.AttestationRoots, cfg.Now, cfg.VerifiedKeysPath, cfg.Logf)
	if err != nil {
		return nil, err
	}
	store, err := openFileInstanceStore(cfg.InstancesPath)
	if err != nil {
		return nil, err
	}
	var indices statuslist.IndexStore = &statuslist.MemoryIndexStore{}
	if cfg.StatusIndicesPath != "" {
		if indices, err = statefile.OpenIndexStore(cfg.StatusIndicesPath); err != nil {
			return nil, fmt.Errorf("walletprovider: %w", err)
		}
	}
	s := &service{
		p: p, cfg: cfg, ev: ev, challenges: newClientLimiter(challengeRate, challengeBurst),
		demo: newDemoVerifier(), store: store,
	}
	if s.lib, err = p.library(cfg, s.demo, store, indices); err != nil {
		return nil, err
	}
	return s, nil
}

type service struct {
	p          *Provider
	cfg        ServiceConfig
	ev         *evidence
	challenges *clientLimiter
	lib        *wp.Provider
	demo       *demoVerifier
	store      *fileInstanceStore

	// mu serializes recording instance keys, so an instance key is
	// recorded for one instance.
	mu sync.Mutex
	// holderKey is the shared instance key Key Attestations are issued
	// for; nil until the first.
	holderKey crypto.PublicKey
}

// library is the library Wallet Provider p's service issues with:
// signed with p's key and certificate, attesting cfg.ClientID, taking
// the demo-only evidence and, with cfg.AndroidApps, Android Key
// Attestation and, with cfg.IOSApps, App Attest.
func (p *Provider) library(cfg ServiceConfig, demo *demoVerifier, store *fileInstanceStore, indices statuslist.IndexStore) (*wp.Provider, error) {
	verifiers := []wp.EvidenceVerifier{demo}
	platforms := map[wp.Platform]wp.PlatformPolicy{
		// Whatever the older protocol's checks found, from a software
		// key to StrongBox, as before.
		DemoPlatform: {SecurityLevels: []wp.SecurityLevel{wp.SecurityLevelSoftware, wp.SecurityLevelTEE, wp.SecurityLevelStrongBox}},
	}
	if len(cfg.IOSApps) > 0 {
		verifiers = append(verifiers, appattest.EvidenceVerifier{Verifier: &appattest.Verifier{
			Apps: cfg.IOSApps, AllowDevelopment: true, Now: cfg.Now,
		}})
		// App Attest vouches for the app, not where its keys are: no
		// key_storage is claimed for them (no KeyStorageRule).
		platforms[wp.PlatformIOS] = wp.PlatformPolicy{SecurityLevels: []wp.SecurityLevel{wp.SecurityLevelSecureEnclave}}
	}
	if len(cfg.AndroidApps) > 0 {
		verifiers = append(verifiers, androidkey.EvidenceVerifier{Verifier: &androidkey.Verifier{
			Apps: cfg.AndroidApps, Revocation: &androidkey.StatusSource{}, Now: cfg.Now,
		}})
		platforms[wp.PlatformAndroid] = wp.PlatformPolicy{
			SecurityLevels:      []wp.SecurityLevel{wp.SecurityLevelTEE, wp.SecurityLevelStrongBox},
			RequireVerifiedBoot: true,
		}
	}
	lib, err := wp.New(wp.Config{
		Identifier: p.Issuer, ClientIDs: []string{cfg.ClientID}, WalletName: WalletName,
		StatusListBaseURI: strings.TrimSuffix(cfg.URL, "/") + wp.StatusPath,
		Policy:            wp.Policy{Platforms: platforms, MaxKeys: maxAttestedKeys},
	}, wp.Dependencies{
		Signer: p.Key, Chain: []*x509.Certificate{p.Certificate},
		Instances: store, InstanceKeys: store.keys(), Challenges: &wp.MemoryChallengeStore{},
		StatusIndices: indices, Evidence: verifiers,
		Clock: cfg.Now, Random: rand.Reader,
		Logger: slog.New(slog.NewTextHandler(logfWriter(cfg.Logf), nil)),
	})
	if err != nil {
		return nil, fmt.Errorf("walletprovider: %w", err)
	}
	return lib, nil
}

// logfWriter writes each slog line through logf.
type logfWriter func(format string, args ...any)

func (w logfWriter) Write(b []byte) (int, error) {
	w("%s", strings.TrimSuffix(string(b), "\n"))
	return len(b), nil
}

func (s *service) challenge(w http.ResponseWriter, r *http.Request) {
	if !s.challenges.allow(clientAddress(r), s.cfg.Now()) {
		writeError(w, http.StatusTooManyRequests, "too many attestation challenges from this address; try again shortly")
		return
	}
	var req ChallengeRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	if req.Purpose != PurposeInstance && req.Purpose != PurposeHolder {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("purpose must be %q or %q", PurposeInstance, PurposeHolder))
		return
	}
	c, err := s.ev.challenge(req.Purpose)
	if errors.Is(err, errTooManyChallenges) {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not make a challenge")
		return
	}
	writeJSON(w, ChallengeResponse{Challenge: base64.RawURLEncoding.EncodeToString(c), ExpiresIn: int(ChallengeLifetime / time.Second)})
}

func (s *service) walletAttestation(w http.ResponseWriter, r *http.Request) {
	var req WalletAttestationRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	if req.ClientID != s.cfg.ClientID {
		writeError(w, http.StatusForbidden, fmt.Sprintf("this Wallet Provider attests only client %q", s.cfg.ClientID))
		return
	}
	key, thumbprint, err := parseP256Key(req.InstanceKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "instance_key: "+err.Error())
		return
	}
	outcome, level, ok := s.checkEvidence(w, "Wallet Attestation", "instance key", PurposeInstance, key, thumbprint, req.InstanceKeyCertificateChain)
	if !ok {
		return
	}
	id, jwt, err := s.libWalletAttestation(r.Context(), key, thumbprint, level)
	switch {
	case errors.Is(err, wp.ErrInstanceRevoked):
		writeError(w, http.StatusForbidden, "this wallet instance is revoked")
		return
	case errors.Is(err, wp.ErrInstanceNotActive):
		writeError(w, http.StatusForbidden, "this wallet instance is suspended")
		return
	case err != nil:
		s.cfg.Logf("wallet provider: Wallet Attestation for instance key %s: %v", thumbprint, err)
	default:
		s.cfg.Logf("wallet provider: Wallet Attestation for instance key %s (instance %s): %s", thumbprint, id, outcome)
	}
	writeAttestation(w, jwt, err)
}

// libWalletAttestation has the library issue a Wallet Attestation for
// the instance key key, whose JWK thumbprint is thumbprint, returning
// it with the key's instance: the instance it's recorded for, or, the
// first time, a new one registered for it, the key recorded at level.
func (s *service) libWalletAttestation(ctx context.Context, key *ecdsa.PublicKey, thumbprint string, level wp.SecurityLevel) (string, string, error) {
	id, err := s.instanceOf(ctx, thumbprint)
	if errors.Is(err, wp.ErrNotFound) {
		return s.newInstanceWalletAttestation(ctx, key, thumbprint, level)
	}
	if err != nil {
		return "", "", err
	}
	jwt, err := s.lib.WalletAttestation(ctx, wp.WalletAttestationRequest{InstanceID: id, ClientID: s.cfg.ClientID, InstanceKey: key})
	return id, jwt, err
}

// newInstanceWalletAttestation registers an instance for the instance
// key key and records the key for it, at level, with its first Wallet
// Attestation.
func (s *service) newInstanceWalletAttestation(ctx context.Context, key *ecdsa.PublicKey, thumbprint string, level wp.SecurityLevel) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, err := s.instanceOf(ctx, thumbprint); !errors.Is(err, wp.ErrNotFound) {
		// Recorded meanwhile, or the store failed.
		if err != nil {
			return "", "", err
		}
		jwt, err := s.lib.WalletAttestation(ctx, wp.WalletAttestationRequest{InstanceID: id, ClientID: s.cfg.ClientID, InstanceKey: key})
		return id, jwt, err
	}
	in, err := s.register(ctx)
	if err != nil {
		return "", "", err
	}
	jwt, err := s.recordInstanceKey(ctx, in.ID, key, level)
	return in.ID, jwt, err
}

// instanceOf is the instance the instance key with thumbprint is
// recorded for, or an error wrapping wp.ErrNotFound.
func (s *service) instanceOf(ctx context.Context, thumbprint string) (string, error) {
	ik, err := s.store.keys().Get(ctx, thumbprint)
	if err != nil {
		return "", err
	}
	return ik.InstanceID, nil
}

// register registers an instance with a registration key of the
// service's own, which signs nothing (the service calls the library
// directly), with demo-only evidence. Callers hold s.mu.
func (s *service) register(ctx context.Context) (wp.Instance, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return wp.Instance{}, err
	}
	ch, raw, err := s.libChallenge(ctx, wp.PurposeRegistration)
	if err != nil {
		return wp.Instance{}, err
	}
	ev, err := s.demo.vouch(raw, demoKey{key: &key.PublicKey, level: wp.SecurityLevelSoftware})
	if err != nil {
		return wp.Instance{}, err
	}
	defer s.demo.forget(ev)
	return s.lib.Register(ctx, wp.RegisterRequest{Challenge: ch, RegistrationKey: &key.PublicKey, Evidence: ev})
}

// recordInstanceKey records key, at level, as an instance key of the
// instance id with demo-only evidence, returning the Wallet
// Attestation that records it. Callers hold s.mu.
func (s *service) recordInstanceKey(ctx context.Context, id string, key crypto.PublicKey, level wp.SecurityLevel) (string, error) {
	ch, raw, err := s.libChallenge(ctx, wp.PurposeInstance)
	if err != nil {
		return "", err
	}
	ev, err := s.demo.vouch(raw, demoKey{key: key, level: level})
	if err != nil {
		return "", err
	}
	defer s.demo.forget(ev)
	return s.lib.WalletAttestation(ctx, wp.WalletAttestationRequest{
		InstanceID: id, ClientID: s.cfg.ClientID, InstanceKey: key, Challenge: ch, Evidence: ev,
	})
}

// libChallenge issues a library challenge for purpose, for the service
// itself to use at once, returning it and its raw bytes.
func (s *service) libChallenge(ctx context.Context, purpose wp.Purpose) (string, []byte, error) {
	ch, err := s.lib.Challenge(ctx, purpose)
	if err != nil {
		return "", nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(ch.Value)
	return ch.Value, raw, err
}

// holderIssuance returns the shared instance Key Attestations are
// issued under, and its one instance key they're issued for: the
// first time, it registers the instance and records an instance key of
// the service's own for it, which signs nothing (its Wallet
// Attestation is discarded).
func (s *service) holderIssuance(ctx context.Context) (string, crypto.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.store.holderInstance()
	if id != "" && s.holderKey != nil {
		return id, s.holderKey, nil
	}
	if id == "" {
		in, err := s.register(ctx)
		if err != nil {
			return "", nil, err
		}
		if err := s.store.setHolderInstance(in.ID); err != nil {
			return "", nil, err
		}
		id = in.ID
	}
	// The key recorded before a restart, or a new one: a restart
	// between registering the instance and recording its key leaves it
	// with none.
	recorded, err := s.store.keys().List(ctx, id, "", 1)
	if err != nil {
		return "", nil, err
	}
	if len(recorded) == 1 {
		key, _, err := parseP256Key(recorded[0].Key)
		if err != nil {
			return "", nil, fmt.Errorf("the holder instance key: %w", err)
		}
		s.holderKey = key
		return id, key, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	if _, err := s.recordInstanceKey(ctx, id, &key.PublicKey, wp.SecurityLevelSoftware); err != nil {
		return "", nil, err
	}
	s.holderKey = &key.PublicKey
	return id, s.holderKey, nil
}

func (s *service) keyAttestation(w http.ResponseWriter, r *http.Request) {
	var req KeyAttestationRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	if len(req.Keys) == 0 || len(req.Keys) > maxAttestedKeys {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("keys must hold 1 to %d keys", maxAttestedKeys))
		return
	}
	if req.CertificateChains != nil && len(req.CertificateChains) != len(req.Keys) {
		writeError(w, http.StatusBadRequest, "certificate_chains must have one chain for each key")
		return
	}
	if !validNonce(req.Nonce) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("nonce must be 1 to %d printable ASCII characters", maxNonceLength))
		return
	}
	var instanceKey crypto.PublicKey
	var instanceID string
	if len(req.InstanceKey) > 0 {
		key, thumbprint, err := parseP256Key(req.InstanceKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "instance_key: "+err.Error())
			return
		}
		id, err := s.instanceOf(r.Context(), thumbprint)
		switch {
		case errors.Is(err, wp.ErrNotFound):
			writeError(w, http.StatusBadRequest, "instance_key isn't one a Wallet Attestation recorded")
			return
		case err != nil:
			s.cfg.Logf("wallet provider: Key Attestation for instance key %s: %v", thumbprint, err)
			writeAttestation(w, "", err)
			return
		}
		instanceKey, instanceID = key, id
	}
	keys := make([]*ecdsa.PublicKey, len(req.Keys))
	thumbprints := make([]string, len(req.Keys))
	for i, raw := range req.Keys {
		key, thumbprint, err := parseP256Key(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("keys[%d]: %v", i, err))
			return
		}
		keys[i], thumbprints[i] = key, thumbprint
	}
	outcomes := make([]string, len(keys))
	vouched := make([]demoKey, len(keys))
	for i, key := range keys {
		var chain []string
		if req.CertificateChains != nil {
			chain = req.CertificateChains[i]
		}
		outcome, level, ok := s.checkEvidence(w, "Key Attestation", fmt.Sprintf("keys[%d]", i), PurposeHolder, key, thumbprints[i], chain)
		if !ok {
			return
		}
		outcomes[i], vouched[i] = outcome, demoKey{key: key, level: level}
	}
	jwt, err := s.issueKeyAttestation(r.Context(), instanceID, instanceKey, vouched, req.Nonce)
	switch {
	case errors.Is(err, wp.ErrInstanceRevoked):
		writeError(w, http.StatusForbidden, "this wallet instance is revoked")
		return
	case errors.Is(err, wp.ErrInstanceNotActive):
		writeError(w, http.StatusForbidden, "this wallet instance is suspended")
		return
	case err != nil:
		s.cfg.Logf("wallet provider: Key Attestation: %v", err)
	default:
		for i, outcome := range outcomes {
			s.cfg.Logf("wallet provider: Key Attestation for holder key %s: %s", thumbprints[i], outcome)
		}
	}
	writeAttestation(w, jwt, err)
}

// issueKeyAttestation has the library issue a Key Attestation over the
// keys vouched for, carrying nonce, for instanceKey of the instance id,
// or with no instanceKey under the shared holder instance.
func (s *service) issueKeyAttestation(ctx context.Context, id string, instanceKey crypto.PublicKey, vouched []demoKey, nonce string) (string, error) {
	if instanceKey == nil {
		var err error
		if id, instanceKey, err = s.holderIssuance(ctx); err != nil {
			return "", err
		}
	}
	ch, raw, err := s.libChallenge(ctx, wp.PurposeHolder)
	if err != nil {
		return "", err
	}
	ev, err := s.demo.vouch(raw, vouched...)
	if err != nil {
		return "", err
	}
	defer s.demo.forget(ev)
	keys := make([]crypto.PublicKey, len(vouched))
	for i, v := range vouched {
		keys[i] = v.key
	}
	res, err := s.lib.KeyAttestation(ctx, wp.KeyAttestationRequest{
		InstanceID: id, InstanceKey: instanceKey, Challenge: ch, Keys: keys, Evidence: []wp.Evidence{ev}, Nonce: nonce,
	})
	if err != nil {
		return "", err
	}
	if len(res.AttestedKeys) != len(keys) {
		return "", fmt.Errorf("the library attested %d of %d keys", len(res.AttestedKeys), len(keys))
	}
	return res.JWT, nil
}

// checkEvidence checks a key's attestation chain, if it was sent one,
// answering 403 and reporting false for one to refuse; it returns what
// it made of it, to log, and the security level the service vouches
// for the key at: StrongBox or the TEE for a hardware chain, software
// for any other, and for a key sent without one.
func (s *service) checkEvidence(w http.ResponseWriter, what, name, purpose string, key *ecdsa.PublicKey, thumbprint string, chain []string) (string, wp.SecurityLevel, bool) {
	if len(chain) == 0 {
		return "no key attestation chain (vouched for by the demo, unverified)", wp.SecurityLevelSoftware, true
	}
	outcome, err := s.ev.check(purpose, key, thumbprint, chain)
	if err == nil && s.cfg.RequireHardwareKeyAttestation && !outcome.Hardware {
		err = fmt.Errorf("this Wallet Provider requires hardware key attestation: %s", strings.Join(outcome.Issues, "; "))
	}
	if err != nil {
		s.cfg.Logf("wallet provider: refused a %s for %s %s: %v", what, name, thumbprint, err)
		writeError(w, http.StatusForbidden, fmt.Sprintf("%s: key attestation: %v", name, err))
		return "", "", false
	}
	return outcome.String(), outcome.level(), true
}

// level is the security level the outcome shows the key is held at.
func (o KeyEvidenceOutcome) level() wp.SecurityLevel {
	switch {
	case !o.Hardware:
		return wp.SecurityLevelSoftware
	case o.KeyMintSecurityLevel == androidattest.StrongBox && o.AttestationSecurityLevel == androidattest.StrongBox:
		return wp.SecurityLevelStrongBox
	}
	return wp.SecurityLevelTEE
}

// decodeRequest reads a JSON request body of at most maxRequestBytes
// into v, answering 400 and reporting false if it can't.
func decodeRequest(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "malformed request: data after the JSON object")
		return false
	}
	return true
}

// validNonce reports whether nonce, signed into a Key Attestation, is a
// plausible c_nonce: 1 to maxNonceLength printable ASCII characters.
func validNonce(nonce string) bool {
	if nonce == "" || len(nonce) > maxNonceLength {
		return false
	}
	for i := 0; i < len(nonce); i++ {
		if nonce[i] < 0x21 || nonce[i] > 0x7e {
			return false
		}
	}
	return true
}

// hasPrivateMember reports whether the JSON object raw has a "d" member
// — EC's private key — under any spelling encoding/json would match, and
// however many times it's repeated (decoding keeps only the last).
func hasPrivateMember(raw json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return false
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return false
		}
		if name, ok := key.(string); ok && strings.EqualFold(name, "d") {
			return true
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return false
		}
	}
	return false
}

// parseP256Key parses raw as a public EC P-256 JWK, returning it with
// its JWK thumbprint (RFC 7638).
func parseP256Key(raw json.RawMessage) (*ecdsa.PublicKey, string, error) {
	var jwk oid4vci.JWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, "", errors.New("not a JWK")
	}
	if hasPrivateMember(raw) {
		return nil, "", errors.New("a private key was sent")
	}
	pub, err := jwk.PublicKey()
	if err != nil {
		return nil, "", err
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, "", errors.New("not an EC P-256 key")
	}
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		return nil, "", err
	}
	return key, thumbprint, nil
}

func writeAttestation(w http.ResponseWriter, jwt string, err error) {
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue the attestation")
		return
	}
	writeJSON(w, AttestationResponse{Attestation: jwt})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
