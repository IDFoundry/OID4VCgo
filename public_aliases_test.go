package oid4vci_test

import (
	"context"
	"crypto"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// These implementations use only public packages, as an integrator's
// module outside this one must: if a resolver interface ever returns a
// type without a public name, this file stops compiling.

type sdjwtResolver struct{}

func (sdjwtResolver) ResolveIssuerKey(context.Context, map[string]any, map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	return nil, oid4vci.ES256, nil
}

type mdocResolver struct{}

func (mdocResolver) ResolveMdocIssuerKey(context.Context, [][]byte, string) (crypto.PublicKey, oid4vci.COSEAlg, error) {
	return nil, oid4vci.COSEES256, nil
}

type attestationResolver struct{}

func (attestationResolver) ResolveAttestationKey(context.Context, attestation.KeyAttestation) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	return nil, oid4vci.EdDSA, nil
}

type proofKeyResolver struct{}

func (proofKeyResolver) ResolveProofBindingKey(context.Context, map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	return nil, oid4vci.ES256, nil
}

func TestResolverInterfacesImplementableWithPublicTypes(t *testing.T) {
	var (
		_ verifier.SDJWTVCIssuerKeyResolver = sdjwtResolver{}
		_ verifier.MdocIssuerKeyResolver    = mdocResolver{}
		_ issuer.AttestationVerifier        = attestationResolver{}
		_ issuer.ProofBindingKeyResolver    = proofKeyResolver{}
	)
	if oid4vci.COSEES256 == oid4vci.COSEEdDSA {
		t.Error("COSE algorithm constants collide")
	}
}
