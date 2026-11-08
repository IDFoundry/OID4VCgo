package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Deferred polling: the issuer defers by a few seconds.
const (
	maxDeferredPolls        = 15
	defaultDeferredInterval = 2 * time.Second
)

// issuance is one run of the core engine.
type issuance struct {
	env      *environment
	w        *wallet.Wallet
	offer    oid4vci.CredentialOffer
	metadata oid4vci.Metadata
	configID string
	resource wallet.ProtectedResourceClient
	holders  []*ecdsa.PrivateKey
}

// runCore runs the core engine, recording into res.
func runCore(ctx context.Context, env *environment, res *result) {
	s := &issuance{env: env}
	var err error
	if s.w, err = env.newWallet(); err != nil {
		res.fail("setup", err)
		return
	}
	if err := s.discover(ctx, res); err != nil {
		return
	}
	if err := s.authorize(ctx, res); err != nil {
		return
	}
	credentials, err := s.requestCredential(ctx, res)
	if err != nil {
		return
	}
	conf := s.metadata.CredentialConfigurationsSupported[s.configID]
	verified := verifyAll(ctx, env, conf, s.offer.CredentialIssuer, credentials, s.holders, res)
	if !verified {
		return
	}
	if env.o.revokeAPIKey != "" {
		if err := revokeFirst(ctx, env, conf, credentials, s.holders, s.offer.CredentialIssuer, res); err != nil {
			res.fail("revoke", err)
			return
		}
	}
	res.OK = true
}

// discover resolves the offer (or makes the wallet's own, naming no
// grant, for a wallet-initiated issuance) and fetches the issuer's
// signed metadata.
func (s *issuance) discover(ctx context.Context, res *result) error {
	o := s.env.o
	var err error
	if o.offer != "" {
		if s.offer, err = s.w.ResolveCredentialOffer(ctx, o.offer); err != nil {
			res.fail("offer", err)
			return err
		}
		if len(s.offer.CredentialConfigurationIDs) == 0 {
			err = errors.New("the offer offers nothing")
			res.fail("offer", err)
			return err
		}
		s.configID = s.offer.CredentialConfigurationIDs[0]
		res.Configuration = s.configID
		if g := s.offer.Grants; g != nil && g.AuthorizationCode != nil {
			res.IssuerState = g.AuthorizationCode.IssuerState != ""
			res.OfferAuthorizationServer = g.AuthorizationCode.AuthorizationServer
		}
	} else {
		s.offer = oid4vci.CredentialOffer{CredentialIssuer: o.issuer, CredentialConfigurationIDs: []string{o.configID}}
		s.configID = o.configID
	}
	if s.metadata, err = s.w.FetchCredentialIssuerMetadata(ctx, s.offer.CredentialIssuer); err != nil {
		res.fail("metadata", err)
		return err
	}
	res.AuthorizationServers = len(s.metadata.AuthorizationServers)
	if _, ok := s.metadata.CredentialConfigurationsSupported[s.configID]; !ok {
		err = fmt.Errorf("the issuer has no configuration %q", s.configID)
		res.fail("metadata", err)
		return err
	}
	return nil
}

// authorize runs PAR, the holder's sign-in and the token request, and
// keeps the DPoP-bound access token's resource client.
func (s *issuance) authorize(ctx context.Context, res *result) error {
	plan, err := wallet.PlanAuthorization(s.offer, s.metadata)
	if err != nil {
		res.fail("plan", err)
		return err
	}
	asMeta, err := s.w.FetchAuthorizationServerMetadata(ctx, plan.AuthorizationServer)
	if err != nil {
		res.fail("as-metadata", err)
		return err
	}
	c, err := s.oauthClient(ctx, asMeta)
	if err != nil {
		res.fail("client", err)
		return err
	}
	authReq, err := wallet.BuildAuthorizationRequestForPlan(s.offer, plan)
	if err != nil {
		res.fail("par", err)
		return err
	}
	session, err := c.BeginAuthorization(ctx, authReq)
	if err != nil {
		res.fail("par", err)
		return err
	}
	redirect, err := login(ctx, s.env.http, session.URL().String(), s.env.o.redirectURI, s.env.o.user, s.env.o.password)
	if err != nil {
		res.fail("login", err)
		return err
	}
	query := redirect[len(s.env.o.redirectURI):]
	if len(query) > 0 && query[0] == '?' {
		query = query[1:]
	}
	completed, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: query, Session: session.Handle()})
	if err != nil {
		res.fail("token", err)
		return err
	}
	success, ok := completed.(client.CompletionSuccess)
	if !ok {
		err = fmt.Errorf("the authorization wasn't granted: %#v", completed)
		res.fail("token", err)
		return err
	}
	res.TokenType = success.Tokens.TokenType
	s.resource = c.ProtectedResource(success.Tokens)
	return nil
}

// oauthClient is the fapigo/client for the Authorization Server,
// authenticating with a Wallet Attestation for a fresh instance key,
// its PoP carrying a challenge from the server's challenge endpoint
// (draft-ietf-oauth-attestation-based-client-auth-07 §8), as walletflow
// builds it.
func (s *issuance) oauthClient(ctx context.Context, asMeta wallet.AuthorizationServerMetadata) (*client.Client, error) {
	issuer, endpoints, err := asMeta.ClientEndpoints()
	if err != nil {
		return nil, err
	}
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	walletAttestation, err := s.env.provider.WalletAttestation(ctx, s.env.o.clientID, instanceKey.Public())
	if err != nil {
		return nil, err
	}
	attestation := client.StaticAttestation(walletAttestation)
	if asMeta.ChallengeEndpoint != "" {
		endpoint, err := fapi.ParseEndpointURL(asMeta.ChallengeEndpoint)
		if err != nil {
			return nil, fmt.Errorf("challenge_endpoint: %w", err)
		}
		attestation = challenged{AttestationSource: attestation, w: s.w, endpoint: endpoint}
	}
	km, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{
		{Purpose: keys.ClientAttestationPoPSigning, Algorithm: fapi.ES256, Signer: instanceKey},
		{Purpose: keys.DPoPProofSigning, Algorithm: fapi.ES256, Signer: dpopKey},
	})
	if err != nil {
		return nil, err
	}
	return client.New(client.Config{
		Issuer: issuer, ClientID: fapi.ClientID(s.env.o.clientID), RedirectURI: s.env.o.redirectURI,
		Endpoints:                      endpoints,
		Profile:                        client.ProfileFAPISecurity,
		Assurance:                      client.AssuranceDevelopment,
		ClientAuthMethod:               storage.ClientAuthMethodAttestation,
		AuthorizationResponseIssPolicy: client.RequireAuthorizationResponseIss,
		OAuthOnly:                      true,
		Algorithms:                     client.Algorithms{DPoP: fapi.ES256, ClientAttestationPoP: fapi.ES256},
		Limits: client.Limits{
			SessionLifetime: 5 * time.Minute, MaxClockSkew: 10 * time.Second,
			HTTPTimeout: 30 * time.Second, MaxHTTPResponseBytes: 2 << 20, MaxJOSECompactBytes: 16 * 1024,
		},
	}, client.Dependencies{
		Sessions: memstore.NewSessionStore(), Keys: km, HTTP: s.env.http,
		Clock: client.SystemClock{}, Random: rand.Reader, Attestation: attestation,
		DPoPNonceCache: client.NewInMemoryDPoPNonceCache(),
	})
}

// challenged is a Wallet Attestation whose PoPs carry a fresh challenge.
type challenged struct {
	client.AttestationSource
	w        *wallet.Wallet
	endpoint fapi.URL
}

// CurrentChallenge implements client.ChallengeSource.
func (c challenged) CurrentChallenge(ctx context.Context) (string, error) {
	return c.w.RequestAttestationChallenge(ctx, c.endpoint)
}

// requestCredential asks for a c_nonce and then the credential, with
// -batch attested keys proved by -proof, encrypted as the metadata
// says, and polls a deferred one; it acknowledges what it received
// with a notification when the issuer asks for one.
func (s *issuance) requestCredential(ctx context.Context, res *result) ([]oid4vci.IssuedCredential, error) {
	if s.metadata.NonceEndpoint == nil {
		err := errors.New("the issuer has no nonce endpoint")
		res.fail("nonce", err)
		return nil, err
	}
	nonce, err := s.w.RequestNonce(ctx, *s.metadata.NonceEndpoint)
	if err != nil {
		res.fail("nonce", err)
		return nil, err
	}
	if user, ok := s.resource.(wallet.DPoPNonceUser); ok && nonce.DPoPNonce != "" {
		endpoint := s.metadata.CredentialEndpoint.URL()
		user.UseDPoPNonce(ctx, &endpoint, nonce.DPoPNonce)
	}
	req, err := s.credentialRequest(ctx, nonce.CNonce)
	if err != nil {
		res.fail("proof", err)
		return nil, err
	}
	reqEnc, respEnc, err := wallet.EncryptionFromMetadata(s.metadata)
	if err != nil {
		res.fail("encryption", err)
		return nil, err
	}
	req.RequestEncryption, req.ResponseEncryption = reqEnc, respEnc
	s.env.encryptedRequest = reqEnc != nil
	result, err := s.w.RequestCredential(ctx, s.resource, s.metadata.CredentialEndpoint, req)
	if err != nil {
		res.fail("credential", err)
		return nil, err
	}
	if result.TransactionID != "" {
		res.Deferred = true
		if result, err = s.pollDeferred(ctx, result, reqEnc, respEnc, res); err != nil {
			res.fail("deferred", err)
			return nil, err
		}
	}
	if len(result.Credentials) == 0 {
		err = errors.New("the credential response carries no credential")
		res.fail("credential", err)
		return nil, err
	}
	if result.NotificationID != "" && s.metadata.NotificationEndpoint != nil {
		if err := s.w.RequestNotification(ctx, s.resource, *s.metadata.NotificationEndpoint, wallet.NotificationRequest{
			NotificationID: result.NotificationID, Event: oid4vci.NotificationEventCredentialAccepted,
		}); err != nil {
			res.fail("notification", err)
			return nil, err
		}
		res.Notified = true
	}
	return result.Credentials, nil
}

// pollDeferred polls the Deferred Credential Endpoint (§9) until the
// credentials arrive.
func (s *issuance) pollDeferred(ctx context.Context, first wallet.CredentialResult, reqEnc *wallet.RequestEncryption, respEnc *wallet.ResponseEncryption, res *result) (wallet.CredentialResult, error) {
	if s.metadata.DeferredCredentialEndpoint == nil {
		return wallet.CredentialResult{}, errors.New("deferred, but the issuer has no deferred credential endpoint")
	}
	result := first
	for range maxDeferredPolls {
		interval := result.Interval
		if interval <= 0 {
			interval = defaultDeferredInterval
		}
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return wallet.CredentialResult{}, ctx.Err()
		}
		res.DeferredPolls++
		next, err := s.w.RequestDeferredCredential(ctx, s.resource, *s.metadata.DeferredCredentialEndpoint, wallet.DeferredCredentialRequest{
			TransactionID: result.TransactionID, RequestEncryption: reqEnc, ResponseEncryption: respEnc,
		})
		if err != nil {
			return wallet.CredentialResult{}, err
		}
		if len(next.Credentials) > 0 {
			return next, nil
		}
		if next.TransactionID == "" {
			return wallet.CredentialResult{}, errors.New("the deferred credential response carries neither credentials nor a transaction_id")
		}
		result = next
	}
	return wallet.CredentialResult{}, fmt.Errorf("still deferred after %d polls", maxDeferredPolls)
}

// credentialRequest makes the -batch holder keys and the -proof that
// proves them.
func (s *issuance) credentialRequest(ctx context.Context, cNonce string) (wallet.CredentialRequest, error) {
	n := max(1, s.env.o.batch)
	s.holders = make([]*ecdsa.PrivateKey, n)
	pubs := make([]*ecdsa.PublicKey, n)
	for i := range s.holders {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return wallet.CredentialRequest{}, err
		}
		s.holders[i], pubs[i] = k, &k.PublicKey
	}
	keyAttestation, err := s.env.provider.KeyAttestation(ctx, nil, pubs, cNonce)
	if err != nil {
		return wallet.CredentialRequest{}, err
	}
	req := wallet.CredentialRequest{CredentialConfigurationID: s.configID, CredentialIssuer: s.offer.CredentialIssuer, Nonce: cNonce}
	switch s.env.o.proof {
	case "attestation":
		req.Attestation = keyAttestation
	case "jwk":
		proof, err := s.w.GenerateProofWithKeyAttestation(s.holders[0], s.offer.CredentialIssuer, cNonce, keyAttestation)
		if err != nil {
			return wallet.CredentialRequest{}, err
		}
		req.JWTProofs = []string{proof}
	case "jwt":
		proof, err := keyIndexProof(s.holders[0], s.offer.CredentialIssuer, cNonce, keyAttestation, time.Now())
		if err != nil {
			return wallet.CredentialRequest{}, err
		}
		req.JWTProofs = []string{proof}
	case "jwt-each":
		// A batch as OpenID4VCI 1.0 §8.2 and §12.2.4 describe it: one
		// key proof per credential, each its own key's, up to
		// batch_size, each with a Key Attestation of that key.
		for i, k := range s.holders {
			ka, err := s.env.provider.KeyAttestation(ctx, nil, []*ecdsa.PublicKey{pubs[i]}, cNonce)
			if err != nil {
				return wallet.CredentialRequest{}, err
			}
			proof, err := keyIndexProof(k, s.offer.CredentialIssuer, cNonce, ka, time.Now())
			if err != nil {
				return wallet.CredentialRequest{}, err
			}
			req.JWTProofs = append(req.JWTProofs, proof)
		}
	default:
		return wallet.CredentialRequest{}, fmt.Errorf("unknown -proof %q", s.env.o.proof)
	}
	return req, nil
}

// keyIndexProof is a jwt proof (OpenID4VCI 1.0 Appendix F.1) signed by
// the first of the keys keyAttestation attests, carrying it in its
// key_attestation header and naming its key by kid "0", its index in
// attested_keys, as ETSI TS 119 472-3 has the EUDI PID Issuer require
// (and F.1 permits: kid, with no jwk or x5c beside it). Package wallet
// conveys the key in jwk instead (GenerateProofWithKeyAttestation), so
// this proof is built here.
func keyIndexProof(signer crypto.Signer, credentialIssuer, nonce, keyAttestation string, now time.Time) (string, error) {
	payload, err := json.Marshal(map[string]any{"aud": credentialIssuer, "iat": now.Unix(), "nonce": nonce})
	if err != nil {
		return "", err
	}
	return jose.Sign(jose.ES256, signer, map[string]any{
		"typ": "openid4vci-proof+jwt", "kid": "0", "key_attestation": keyAttestation,
	}, payload)
}
