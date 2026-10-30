package certchain

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

// The ISO/IEC 18013-5 Annex B extended key usages the default leaf
// policies tell roles apart by.
var (
	// MDLDocumentSignerEKU is an mDL document signer's (Annex B.1.4:
	// id-mdl-kp-mdlDS, 1.0.18013.5.1.2).
	MDLDocumentSignerEKU = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}
	// ReaderAuthenticationEKU is an mdoc reader authentication
	// certificate's (Annex B.1.7: 1.0.18013.5.1.6).
	ReaderAuthenticationEKU = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}
)

// isoRoleNames name the certificates the ISO/IEC 18013-5 extended key
// usages above mark, for errors.
var isoRoleNames = map[string]string{
	MDLDocumentSignerEKU.String():    "an mDL document signer certificate",
	ReaderAuthenticationEKU.String(): "an mdoc reader authentication certificate",
}

// otherRoleEKUs are the extended key usages (RFC 5280 §4.2.1.12, and
// the vendor ones crypto/x509 names) that denote a role other than
// signing credentials, attestations or registrations: TLS, code
// signing, email, time stamping, OCSP, IPsec. That's every one
// crypto/x509 names but anyExtendedKeyUsage.
var otherRoleEKUs = []x509.ExtKeyUsage{
	x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning,
	x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning,
	x509.ExtKeyUsageIPSECEndSystem, x509.ExtKeyUsageIPSECTunnel, x509.ExtKeyUsageIPSECUser,
	x509.ExtKeyUsageMicrosoftServerGatedCrypto, x509.ExtKeyUsageNetscapeServerGatedCrypto,
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning, x509.ExtKeyUsageMicrosoftKernelCodeSigning,
}

// CheckSigningLeaf refuses a leaf certificate that can't be a signer's
// in any of this library's roles: one whose key usage extension doesn't
// allow digital signatures, or that is an OCSP signer. name is the
// certificate as the error names it ("the issuer certificate").
func CheckSigningLeaf(name string, leaf *x509.Certificate) error {
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("%s's key usage doesn't allow digital signatures", name)
	}
	if slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return fmt.Errorf("%s is an OCSP signer's", name)
	}
	return nil
}

// LeafRole is a signing role's default leaf policy, which the
// LeafPolicy defaults of verifier.X5CIssuerKeyResolver,
// issuer.X5CAttestationVerifier and X5CProofBindingKeyResolver, and
// registration.Registrars share. Chain validation alone accepts any
// certificate under the roots, so a certificate issued for another role
// under roots shared with it — a TLS server's, an mdoc reader's —
// would otherwise sign for this one.
type LeafRole struct {
	// Name is the certificate as errors name it ("the issuer
	// certificate").
	Name string

	// OtherISOEKUs are the ISO/IEC 18013-5 extended key usages that
	// denote a role other than this one.
	OtherISOEKUs []asn1.ObjectIdentifier

	// Strict refuses a leaf whose extended key usage lists any other
	// role's purpose. Otherwise a leaf is refused for its extended key
	// usage only when it lists nothing but other roles' purposes, or an
	// ISO/IEC 18013-5 one of OtherISOEKUs.
	Strict bool
}

// Check is the policy, with a LeafPolicy's signature: it refuses a leaf
// CheckSigningLeaf refuses, one whose extended key usage lists one of
// OtherISOEKUs, and one whose extended key usage denotes another role
// (see Strict). It refuses the leaf, too, when every verified path in
// chains (leaf first, as a LeafPolicy receives them) has an
// intermediate CA whose extended key usage lists only other roles'
// purposes: a CA restricted to issuing TLS certificates, say. A leaf
// without these extensions, or whose extended key usage lists
// anyExtendedKeyUsage or a purpose of its own (a private one), passes.
func (r LeafRole) Check(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
	if leaf == nil {
		return errors.New("no leaf certificate")
	}
	if err := CheckSigningLeaf(r.Name, leaf); err != nil {
		return err
	}
	if i := slices.IndexFunc(leaf.UnknownExtKeyUsage, r.isOtherISOEKU); i >= 0 {
		return fmt.Errorf("%s is %s (ISO/IEC 18013-5 Annex B)", r.Name, isoRoleNames[leaf.UnknownExtKeyUsage[i].String()])
	}
	if r.Strict && r.listsOtherRole(leaf) {
		return fmt.Errorf("%s's extended key usage lists another role's purpose (TLS, code signing, email, time stamping, IPsec)", r.Name)
	}
	if r.onlyOtherRoles(leaf) {
		return fmt.Errorf("%s's extended key usage lists only other roles' purposes (TLS, code signing, email, time stamping, IPsec)", r.Name)
	}
	if len(chains) > 0 && !slices.ContainsFunc(chains, r.intermediatesAllow) {
		return errors.New("an intermediate CA on every verified path restricts its extended key usage to other roles' purposes")
	}
	return nil
}

func (r LeafRole) isOtherISOEKU(oid asn1.ObjectIdentifier) bool {
	return slices.ContainsFunc(r.OtherISOEKUs, oid.Equal)
}

// listsOtherRole reports whether cert's extended key usage lists a
// purpose crypto/x509 names other than anyExtendedKeyUsage.
func (r LeafRole) listsOtherRole(cert *x509.Certificate) bool {
	return slices.ContainsFunc(cert.ExtKeyUsage, func(eku x509.ExtKeyUsage) bool { return slices.Contains(otherRoleEKUs, eku) })
}

// onlyOtherRoles reports whether cert's extended key usage lists
// purposes, each one denoting another role.
func (r LeafRole) onlyOtherRoles(cert *x509.Certificate) bool {
	if cert == nil || len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage) == 0 {
		return false
	}
	for _, eku := range cert.ExtKeyUsage {
		if !slices.Contains(otherRoleEKUs, eku) {
			return false
		}
	}
	return !slices.ContainsFunc(cert.UnknownExtKeyUsage, func(oid asn1.ObjectIdentifier) bool { return !r.isOtherISOEKU(oid) })
}

// intermediatesAllow reports whether no intermediate of chain (the
// certificates between its leaf and its trust anchor) restricts its
// extended key usage to other roles' purposes.
func (r LeafRole) intermediatesAllow(chain []*x509.Certificate) bool {
	if len(chain) < 3 {
		return true
	}
	return !slices.ContainsFunc(chain[1:len(chain)-1], r.onlyOtherRoles)
}
