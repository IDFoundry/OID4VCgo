package certrevocation

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
)

// signedListParts are the parts of a DER CertificateList (RFC 5280
// §5.1) that checking its signature takes, read without parsing the
// rest: the signed tbsCertList, the issuer Name inside it, the
// signatureAlgorithm and the signatureValue.
type signedListParts struct {
	tbs, issuer, algorithm, signature []byte
}

// errMalformedList is a CertificateList that splitSignedList can't
// split. It quotes nothing of the list, as a fetch's errors mustn't.
var errMalformedList = errors.New("malformed CertificateList")

// splitSignedList reads der as
//
//	CertificateList ::= SEQUENCE {
//	    tbsCertList          TBSCertList,
//	    signatureAlgorithm   AlgorithmIdentifier,
//	    signatureValue       BIT STRING }
//
// with nothing after it or after its signatureValue, and from the
// tbsCertList only its optional version, its signature
// AlgorithmIdentifier, which must be byte for byte the outer one, and
// its issuer. The entries, times and extensions after them are left
// unread: they're what makes parsing a list cost in proportion to its
// size.
func splitSignedList(der []byte) (signedListParts, error) {
	list, rest, err := derElement(der, asn1.TagSequence)
	if err != nil || len(rest) != 0 {
		return signedListParts{}, errMalformedList
	}
	tbs, rest, err := derElement(list.Bytes, asn1.TagSequence)
	if err != nil {
		return signedListParts{}, errMalformedList
	}
	algorithm, rest, err := derElement(rest, asn1.TagSequence)
	if err != nil {
		return signedListParts{}, errMalformedList
	}
	var signature asn1.BitString
	if rest, err = asn1.Unmarshal(rest, &signature); err != nil || len(rest) != 0 {
		return signedListParts{}, errMalformedList
	}
	fields := tbs.Bytes
	if _, after, err := derElement(fields, asn1.TagInteger); err == nil {
		fields = after // version
	}
	inner, fields, err := derElement(fields, asn1.TagSequence)
	if err != nil {
		return signedListParts{}, errMalformedList
	}
	if !bytes.Equal(inner.FullBytes, algorithm.FullBytes) {
		return signedListParts{}, errors.New("the CRL's inner and outer signature algorithms differ")
	}
	issuer, _, err := derElement(fields, asn1.TagSequence)
	if err != nil {
		return signedListParts{}, errMalformedList
	}
	return signedListParts{tbs: tbs.FullBytes, issuer: issuer.FullBytes, algorithm: algorithm.FullBytes, signature: signature.RightAlign()}, nil
}

// derElement reads one DER element of the universal class with tag
// from the front of b, returning it and what follows. encoding/asn1
// reads only its tag and length, and refuses the indefinite and
// non-minimal lengths x509.ParseRevocationList refuses.
func derElement(b []byte, tag int) (asn1.RawValue, []byte, error) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(b, &v)
	if err != nil {
		return v, nil, err
	}
	if v.Class != asn1.ClassUniversal || v.Tag != tag || v.IsCompound != (tag == asn1.TagSequence) {
		return v, nil, errMalformedList
	}
	return v, rest, nil
}

// signedByOneOf is whether one of issuers, by its name and key, signed
// the CertificateList der, checked over der's raw tbsCertList without
// parsing the list. It refuses what splitSignedList can't split.
//
// It is what a fetched list must pass before x509.ParseRevocationList
// parses it, so a list from anyone else costs no more than this, not a
// parse in proportion to its size. A list it passes is then checked in
// full, its signature by RevocationList.CheckSignatureFrom again, as
// every other list is: this check only orders that work, it doesn't
// replace any of it.
func signedByOneOf(der []byte, issuers []*x509.Certificate) (bool, error) {
	parts, err := splitSignedList(der)
	if err != nil {
		return false, err
	}
	algorithm := x509.UnknownSignatureAlgorithm
	mapped := false
	for _, issuer := range issuers {
		if !bytes.Equal(issuer.RawSubject, parts.issuer) {
			continue
		}
		if !mapped {
			algorithm, mapped = signatureAlgorithmOf(parts.algorithm), true
		}
		if issuer.CheckSignature(algorithm, parts.tbs, parts.signature) == nil {
			return true, nil
		}
	}
	return false, nil
}

// The fixed parts of the CertificateList signatureAlgorithmOf parses:
// a version of v2, an empty issuer Name, a thisUpdate, and an empty
// signatureValue.
var (
	probeVersion   = []byte{0x02, 0x01, 0x01}
	probeIssuer    = []byte{0x30, 0x00}
	probeTime      = append([]byte{0x17, 0x0d}, "250101000000Z"...)
	probeSignature = []byte{0x03, 0x01, 0x00}
)

// signatureAlgorithmOf is the x509.SignatureAlgorithm the DER
// AlgorithmIdentifier ai names, exactly as x509.ParseRevocationList
// maps it — the RSA-PSS parameters it takes included — or
// x509.UnknownSignatureAlgorithm. The standard library's table isn't
// exported, so this parses a CertificateList of nothing but ai: the
// mapping is then always the one RevocationList.CheckSignatureFrom
// verifies under, in whichever Go version this is built with, and an
// algorithm a later version adds is verified here too, rather than
// refused.
func signatureAlgorithmOf(ai []byte) x509.SignatureAlgorithm {
	tbs := derSequence(probeVersion, ai, probeIssuer, probeTime)
	list, err := x509.ParseRevocationList(derSequence(tbs, ai, probeSignature))
	if err != nil {
		return x509.UnknownSignatureAlgorithm
	}
	return list.SignatureAlgorithm
}

// derSequence is the DER SEQUENCE of the DER elements parts.
func derSequence(parts ...[]byte) []byte {
	der, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(parts, nil)})
	if err != nil {
		return nil
	}
	return der
}
