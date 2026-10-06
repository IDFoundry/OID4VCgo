package proximity

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/readerauth"
)

// ReaderTrust is which mdoc readers a holder recognizes, for
// VerifyReaderAuth.
type ReaderTrust struct {
	// Roots are the trust anchors a reader's certificate must chain to;
	// a nil pool recognizes no reader (never the system's roots).
	Roots *x509.CertPool
	// LeafPolicy, if set, is run on the chain-verified reader
	// certificate and its verified paths, and can refuse it. Chain
	// validation accepts a leaf with any key usage:
	// RequireReaderAuthenticationEKU requires what Annex B profiles a
	// reader authentication certificate with.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// Now is when the certificates must be valid; zero: the current
	// time.
	Now time.Time
}

// ReaderAuthenticationEKU is the extended key usage of an mdoc reader
// authentication certificate (Annex B.1.7: 1.0.18013.5.1.6).
var ReaderAuthenticationEKU = readerauth.EKU

// RequireReaderAuthenticationEKU is a ReaderTrust.LeafPolicy refusing a
// reader certificate without ReaderAuthenticationEKU.
func RequireReaderAuthenticationEKU(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
	return readerauth.RequireEKU(leaf, chains)
}

// ReaderStatus is what VerifyReaderAuth found out about who sent a
// request.
type ReaderStatus int

const (
	// ReaderUnauthenticated: the request carries no readerAuth. Reader
	// authentication is optional (§9.1.4), and an mDL must release its
	// mandatory elements without it (§7.2.1).
	ReaderUnauthenticated ReaderStatus = iota
	// ReaderTrusted: readerAuth verifies by a certificate that chains
	// to ReaderTrust.Roots and passes its LeafPolicy.
	ReaderTrusted
	// ReaderUntrusted: readerAuth verifies by the certificate it
	// carries, which doesn't chain to ReaderTrust.Roots or fails its
	// LeafPolicy. Whoever holds that key signed the request; what the
	// certificate says about them is unproven.
	ReaderUntrusted
	// ReaderInvalid: readerAuth is malformed, or its signature doesn't
	// verify over this session's request: it proves nothing, and may
	// be replayed from another session.
	ReaderInvalid
)

func (s ReaderStatus) String() string {
	switch s {
	case ReaderUnauthenticated:
		return "unauthenticated"
	case ReaderTrusted:
		return "trusted"
	case ReaderUntrusted:
		return "untrusted"
	case ReaderInvalid:
		return "invalid"
	default:
		return fmt.Sprintf("ReaderStatus(%d)", int(s))
	}
}

// ReaderAuthentication is VerifyReaderAuth's result.
type ReaderAuthentication struct {
	Status ReaderStatus
	// Chain is the certificate chain readerAuth carries, leaf first, as
	// received: for ReaderTrusted the reader's verified identity; for
	// ReaderUntrusted the claims of whoever signed; and nil otherwise,
	// unless ReaderInvalid's certificates parsed.
	Chain []*x509.Certificate
	// Err is why Status isn't ReaderTrusted; nil when it is.
	Err error
}

// VerifyReaderAuth checks req's readerAuth (§9.1.4): a signature over
// ReaderAuthentication, this session's SessionTranscript and req's
// ItemsRequestBytes, by the certificate it carries, which should chain
// to t.Roots. Call it after HandleSessionEstablishment, before the
// consent prompt, which shows the result.
func (s *DeviceSession) VerifyReaderAuth(req DocRequest, t ReaderTrust) ReaderAuthentication {
	return VerifyReaderAuth(req, s.sessionTranscriptBytes, t)
}

// VerifyReaderAuth is DeviceSession.VerifyReaderAuth for the session
// whose SessionTranscriptBytes is sessionTranscriptBytes.
func VerifyReaderAuth(req DocRequest, sessionTranscriptBytes []byte, t ReaderTrust) ReaderAuthentication {
	if len(req.ReaderAuth) == 0 {
		return ReaderAuthentication{Status: ReaderUnauthenticated, Err: errors.New("the request carries no reader authentication")}
	}
	ders, chain, err := readerauth.Chain(req.ReaderAuth)
	if err != nil {
		return ReaderAuthentication{Status: ReaderInvalid, Err: err}
	}
	detached, err := readerAuthenticationBytes(sessionTranscriptBytes, req.ItemsRequestBytes)
	if err != nil {
		return ReaderAuthentication{Status: ReaderInvalid, Chain: chain, Err: err}
	}
	if err := readerauth.VerifySignature(req.ReaderAuth, detached, chain[0]); err != nil {
		return ReaderAuthentication{Status: ReaderInvalid, Chain: chain, Err: err}
	}
	if _, err := readerauth.VerifyTrust(ders, readerauth.Trust{Roots: t.Roots, LeafPolicy: t.LeafPolicy, Now: t.Now}); err != nil {
		return ReaderAuthentication{Status: ReaderUntrusted, Chain: chain, Err: err}
	}
	return ReaderAuthentication{Status: ReaderTrusted, Chain: chain}
}

// readerAuthenticationBytes is §9.1.4's ReaderAuthenticationBytes,
// #6.24(bstr .cbor ["ReaderAuthentication", SessionTranscript,
// ItemsRequestBytes]): what readerAuth signs, detached.
func readerAuthenticationBytes(sessionTranscriptBytes, itemsRequestBytes []byte) ([]byte, error) {
	if len(sessionTranscriptBytes) == 0 {
		return nil, errors.New("proximity: no session transcript (session not established)")
	}
	transcript, err := unwrapTag24(sessionTranscriptBytes)
	if err != nil {
		return nil, fmt.Errorf("proximity: decode SessionTranscriptBytes: %w", err)
	}
	authentication, err := encMode.Marshal([]any{"ReaderAuthentication", cbor.RawMessage(transcript), cbor.RawMessage(itemsRequestBytes)})
	if err != nil {
		return nil, fmt.Errorf("proximity: encode ReaderAuthentication: %w", err)
	}
	b, err := wrapTag24(authentication)
	if err != nil {
		return nil, fmt.Errorf("proximity: encode ReaderAuthenticationBytes: %w", err)
	}
	return b, nil
}

// readerKey is the key and chain WithReaderAuth sets.
type readerKey struct {
	signer crypto.Signer
	chain  []*x509.Certificate
}

// sign is the readerAuth for itemsRequestBytes in the session whose
// SessionTranscriptBytes is sessionTranscriptBytes.
func (k readerKey) sign(sessionTranscriptBytes, itemsRequestBytes []byte) ([]byte, error) {
	detached, err := readerAuthenticationBytes(sessionTranscriptBytes, itemsRequestBytes)
	if err != nil {
		return nil, err
	}
	sig, err := readerauth.Sign(k.signer, k.chain, detached)
	if err != nil {
		return nil, fmt.Errorf("proximity: sign readerAuth: %w", err)
	}
	return sig, nil
}
