package walletprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/attestation"
)

// A Key Attestation carries the status of the instance key the request
// names only when the request proves it holds that key. An instance key
// is no secret, the cnf of each Wallet Attestation, so a request naming
// another wallet's without the proof gets the shared holder instance's
// status, and one with a proof that isn't the key's, or that was made
// for other keys or another nonce, is refused.
func TestService_KeyAttestationProvesTheInstanceKey(t *testing.T) {
	_, c := newService(t)
	ctx := context.Background()
	status := func(jwt string) string { return fmt.Sprint(jwtClaims(t, jwt)["status"]) }

	victim, attacker, holder := p256(t), p256(t), p256(t)
	wa, err := c.WalletAttestation(ctx, "wallet-1", &victim.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	shared := status(sharedKeyAttestation(t, c, &holder.PublicKey))

	// The wallet itself proves its instance key: its status.
	ka, err := c.ProvenKeyAttestation(ctx, victim, []*ecdsa.PublicKey{&holder.PublicKey}, "n")
	if err != nil {
		t.Fatal(err)
	}
	if status(ka) != status(wa) {
		t.Errorf("a proven instance key's Key Attestation: status %s, want its instance's %s", status(ka), status(wa))
	}

	// Another naming it without proof: the shared holder instance's.
	ka, err = c.KeyAttestation(ctx, &victim.PublicKey, []*ecdsa.PublicKey{&attacker.PublicKey}, "n")
	if err != nil {
		t.Fatal(err)
	}
	if status(ka) == status(wa) || status(ka) != shared {
		t.Errorf("an unproven instance key's Key Attestation: status %s, want the shared holder instance's %s, not the named instance's", status(ka), shared)
	}

	proof := func(signer crypto.Signer, nonce string, keys ...*ecdsa.PublicKey) string {
		return instanceProof(t, signer, nonce, keys...)
	}
	send := func(proof string) error {
		instanceJWK, _ := attestation.AttestedKey(&victim.PublicKey)
		keyJWK, _ := attestation.AttestedKey(&attacker.PublicKey)
		_, err := c.post(ctx, KeyAttestationPath, KeyAttestationRequest{
			InstanceKey: instanceJWK, InstanceKeyProof: proof, Keys: []json.RawMessage{keyJWK}, Nonce: "n",
		})
		return err
	}
	for name, p := range map[string]string{
		"signed by another key":     proof(attacker, "n", &attacker.PublicKey),
		"made for other keys":       proof(victim, "n", &holder.PublicKey),
		"made for another nonce":    proof(victim, "m", &attacker.PublicKey),
		"not base64url":             "!!",
		"longer than any signature": strings.Repeat("A", maxInstanceKeyProofLength+1),
	} {
		if err := send(p); err == nil || !strings.Contains(err.Error(), "instance_key_proof") {
			t.Errorf("a proof %s: %v, want refused", name, err)
		}
	}
	if err := send(proof(victim, "n", &attacker.PublicKey)); err != nil {
		t.Errorf("the instance key's own proof: %v", err)
	}
}

// instanceProof is signer's instance_key_proof over nonce and keys.
func instanceProof(t *testing.T, signer crypto.Signer, nonce string, keys ...*ecdsa.PublicKey) string {
	t.Helper()
	thumbprints := make([]string, len(keys))
	for i, k := range keys {
		jwk, err := attestation.AttestedKey(k)
		if err != nil {
			t.Fatal(err)
		}
		if _, thumbprints[i], err = parseP256Key(jwk); err != nil {
			t.Fatal(err)
		}
	}
	digest := instanceKeyProofDigest(nonce, thumbprints)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(sig)
}
