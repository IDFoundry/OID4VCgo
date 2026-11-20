package issuer_test

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testjose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// deferredProofs builds the proofs of a request to defer, carrying the
// c_nonce n, and names their proof type.
type deferredProofs func(t *testing.T, f deferralFixture, n string) (string, []string)

// jwkProof is a jwt proof by a new key for alg, ES256 or ES384,
// conveyed by jwk.
func jwkProof(alg string) deferredProofs {
	return func(t *testing.T, _ deferralFixture, n string) (string, []string) {
		curve := elliptic.P256()
		if alg == oid4vci.ES384 {
			curve = elliptic.P384()
		}
		key := newECKey(t, curve)
		var jwkObj map[string]any
		if err := json.Unmarshal(jwkJSON(t, &key.PublicKey), &jwkObj); err != nil {
			t.Fatal(err)
		}
		return oid4vci.ProofTypeJWT, []string{testjose.SignClaims(t, alg, key,
			map[string]any{"typ": "openid4vci-proof+jwt", "jwk": jwkObj},
			map[string]any{"aud": testIssuer, "iat": time.Now().Unix(), "nonce": n})}
	}
}

// keyAttestedProof is a jwt proof by a P-256 key, carrying a key
// attestation that asserts keyStorage and attests the key and, unless
// alsoFor is "", a key for alsoFor.
func keyAttestedProof(keyStorage []attestation.AttackPotentialResistance, alsoFor string) deferredProofs {
	return func(t *testing.T, f deferralFixture, n string) (string, []string) {
		holder := testP256Key(t)
		keys := []crypto.PublicKey{&holder.PublicKey}
		if alsoFor != "" {
			keys = append(keys, publicKeyFor(t, alsoFor))
		}
		ka := keyAttestationWith(t, f.attestationSigner, attestation.Header{}, n, false, keyStorage, keys...)
		return oid4vci.ProofTypeJWT, []string{jwtProofWithKeyAttestation(t, holder, n, ka)}
	}
}

// besideJWKProof is proofs and a jwt proof by another P-256 key,
// conveyed by jwk, with no key attestation.
func besideJWKProof(proofs deferredProofs) deferredProofs {
	return func(t *testing.T, f deferralFixture, n string) (string, []string) {
		proofType, values := proofs(t, f, n)
		return proofType, append(values, buildJWTProof(t, testP256Key(t), testIssuer, n))
	}
}

// attestationProof is an attestation proof attesting a P-256 key and
// asserting keyStorage.
func attestationProof(keyStorage []attestation.AttackPotentialResistance) deferredProofs {
	return func(t *testing.T, f deferralFixture, n string) (string, []string) {
		return oid4vci.ProofTypeAttestation, []string{keyAttestationWith(t, f.attestationSigner, attestation.Header{}, n, false, keyStorage, &testP256Key(t).PublicKey)}
	}
}

// requiring has the configuration's proofType require key attestations
// meeting req.
func requiring(proofType string, req oid4vci.KeyAttestationRequirement) func(*issuer.CredentialConfiguration) {
	return func(c *issuer.CredentialConfiguration) {
		ptc := c.ProofTypesSupported[proofType]
		ptc.KeyAttestationsRequired = &req
		c.ProofTypesSupported[proofType] = ptc
	}
}

// restartedUnder is f's Credential Issuer started again on f's stores
// and clock, with change made to its SD-JWT VC configuration, still
// trusting f's key attestation signer, and with deps changed by mutate.
func restartedUnder(t *testing.T, f deferralFixture, change func(*issuer.CredentialConfiguration), mutate ...func(*issuer.Dependencies)) *issuer.Issuer {
	t.Helper()
	return newDeferralFixture(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
		change(&c)
		cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = c
		deps.DeferredTransactions, deps.Clock = f.store, f.clock
		deps.AttestationVerifier = fixedAttestationVerifier{pub: &f.attestationSigner.PublicKey, alg: jose.ES256}
		for _, m := range mutate {
			m(deps)
		}
	}).iss
}

// IssueDeferredCredential holds a transaction's binding keys to its
// credential configuration as it is then, as RequestCredential holds a
// request's: when the configuration changes while the transaction is
// pending, and the issuer restarts on the same stores, the transaction
// is denied with ErrDeferredProofPolicy once its keys no longer meet
// it, and issues while they do. The fixture's configuration takes jwt
// and attestation proofs signed ES256, and requires no key attestation.
// A record whose key attestations name no proof type, saved before
// KeyAttestationProofType existed, meets either proof type.
func TestDeferral_HeldToTheConfigurationNow(t *testing.T) {
	moderate := []attestation.AttackPotentialResistance{attestation.ISO18045Moderate}
	moderateStorage := oid4vci.KeyAttestationRequirement{KeyStorage: []string{string(attestation.ISO18045Moderate)}}
	high := []string{string(attestation.ISO18045High)}
	highStorage := oid4vci.KeyAttestationRequirement{KeyStorage: high}
	takingES384 := withProofAlgs([]string{oid4vci.ES256, oid4vci.ES384}, []string{oid4vci.ES256})
	unchanged := func(*issuer.CredentialConfiguration) {}
	requiringEach := func(jwt, att oid4vci.KeyAttestationRequirement) func(*issuer.CredentialConfiguration) {
		return func(c *issuer.CredentialConfiguration) {
			requiring(oid4vci.ProofTypeJWT, jwt)(c)
			requiring(oid4vci.ProofTypeAttestation, att)(c)
		}
	}
	for name, tc := range map[string]struct {
		before func(*issuer.Config, *issuer.Dependencies)
		proofs deferredProofs
		legacy bool // the record names no proof type
		after  func(*issuer.CredentialConfiguration)
		denied bool
	}{
		"unchanged": {proofs: jwkProof(oid4vci.ES256), after: unchanged},
		"a key attestation now required": {
			proofs: jwkProof(oid4vci.ES256), after: requiring(oid4vci.ProofTypeJWT, oid4vci.KeyAttestationRequirement{}), denied: true,
		},
		"jwt proofs no longer taken": {
			proofs: jwkProof(oid4vci.ES256), after: func(c *issuer.CredentialConfiguration) { delete(c.ProofTypesSupported, oid4vci.ProofTypeJWT) }, denied: true,
		},
		"its key's algorithm no longer taken": {
			before: takingES384, proofs: jwkProof(oid4vci.ES384), after: unchanged, denied: true,
		},
		"the key_storage it asserts still accepted": {
			proofs: keyAttestedProof(moderate, ""), after: requiring(oid4vci.ProofTypeJWT, moderateStorage),
		},
		"a higher key_storage now required": {
			proofs: keyAttestedProof(moderate, ""), after: requiring(oid4vci.ProofTypeJWT, highStorage), denied: true,
		},
		"user_authentication now required": {
			proofs: keyAttestedProof(moderate, ""), after: requiring(oid4vci.ProofTypeJWT, oid4vci.KeyAttestationRequirement{UserAuthentication: high}), denied: true,
		},
		"a key no key attestation attests, now required": {
			proofs: besideJWKProof(keyAttestedProof(moderate, "")), after: requiring(oid4vci.ProofTypeJWT, oid4vci.KeyAttestationRequirement{}), denied: true,
		},
		"an attested key's algorithm no longer taken": {
			before: takingES384, proofs: keyAttestedProof(nil, oid4vci.ES384), after: unchanged, denied: true,
		},
		"attestation proof, a higher key_storage now required": {
			proofs: attestationProof(moderate), after: requiring(oid4vci.ProofTypeAttestation, highStorage), denied: true,
		},
		"no proof type recorded, one proof type's key_storage met": {
			proofs: keyAttestedProof(moderate, ""), legacy: true, after: requiringEach(highStorage, moderateStorage),
		},
		"no proof type recorded, neither proof type's key_storage met": {
			proofs: keyAttestedProof(moderate, ""), legacy: true, after: requiringEach(highStorage, highStorage), denied: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			var before []func(*issuer.Config, *issuer.Dependencies)
			if tc.before != nil {
				before = append(before, tc.before)
			}
			f := newDeferralFixture(t, before...)
			proofType, proofs := tc.proofs(t, f, f.issueNonce(t))
			txID := deferProofsOf(t, f, proofType, proofs...)
			ctx := context.Background()
			if tc.legacy {
				if err := f.store.Update(ctx, txID, func(r *issuer.DeferredTransactionRecord) error {
					r.KeyAttestationProofType = ""
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			iss := restartedUnder(t, f, tc.after)
			err := iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()})
			res, pollErr := iss.RequestDeferredCredential(ctx, deferralAuth, issuer.DeferredCredentialRequest{TransactionID: txID})
			if !tc.denied {
				if err != nil || pollErr != nil || len(res.Credentials) == 0 {
					t.Fatalf("IssueDeferredCredential = %v; poll = %d credentials, %v; want them issued", err, len(res.Credentials), pollErr)
				}
				return
			}
			if !errors.Is(err, issuer.ErrDeferredProofPolicy) {
				t.Fatalf("IssueDeferredCredential = %v, want ErrDeferredProofPolicy", err)
			}
			assertIssuerError(t, pollErr, issuer.ErrorCredentialRequestDenied)
		})
	}
}

// While a key attestation's status can't be decided, a transaction
// whose configuration now requires key attestations stays pending,
// since that attestation could attest any of its keys, and it issues
// once the status can be checked and the keys meet the requirement.
func TestDeferral_HeldToTheConfigurationNowWhileUndecided(t *testing.T) {
	f := newDeferralFixture(t)
	proofType, proofs := keyAttestedProof(nil, "")(t, f, f.issueNonce(t))
	txID := deferProofsOf(t, f, proofType, proofs...)
	status := errors.New("the Status List couldn't be fetched")
	iss := restartedUnder(t, f, requiring(oid4vci.ProofTypeJWT, oid4vci.KeyAttestationRequirement{}), func(deps *issuer.Dependencies) {
		deps.AttestationStatus = attestationStatusFunc(func(context.Context, issuer.VerifiedKeyAttestation) error { return status })
	})
	ctx := context.Background()
	err := iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()})
	if !errors.Is(err, issuer.ErrDeferredAttestationStatusUnknown) || errors.Is(err, issuer.ErrDeferredProofPolicy) {
		t.Fatalf("IssueDeferredCredential = %v, want ErrDeferredAttestationStatusUnknown, the transaction kept", err)
	}
	status = nil
	if err := iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); err != nil {
		t.Fatalf("IssueDeferredCredential once the status can be checked: %v", err)
	}
}
