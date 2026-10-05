package proximity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// ReaderSession is the mdoc reader (verifier) side of one proximity
// session: it reads the mdoc's QR engagement, sends one request and
// verifies the response. It isn't safe for concurrent use.
type ReaderSession struct {
	eReaderKey      *ecdsa.PrivateKey
	eReaderKeyBytes []byte // the COSE_Key, as sent in EReaderKeyBytes
	engagement      parsedEngagement

	sessionTranscriptBytes []byte
	cipher                 *cipherState
	readerAuth             crypto.Signer

	docType   string
	requested requestedSet
	sent      bool
	closed    bool
}

type readerConfig struct {
	readerAuth crypto.Signer
}

// ReaderOption configures NewReaderSession.
type ReaderOption func(*readerConfig)

// WithReaderAuth sets the key that would sign readerAuth (§9.1.4).
// Reader authentication isn't implemented yet: with a signer set,
// Establishment returns an error rather than send an unsigned request.
func WithReaderAuth(signer crypto.Signer) ReaderOption {
	return func(c *readerConfig) { c.readerAuth = signer }
}

// NewReaderSession decodes the mdoc's QR code (§8.2.2.3), checks its
// DeviceEngagement offers cipher suite 1, generates the reader's
// ephemeral key (EReaderKey) and derives the session keys (§9.1.5).
func NewReaderSession(qr string, opts ...ReaderOption) (*ReaderSession, error) {
	var cfg readerConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	de, err := decodeQR(qr)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proximity: generate EReaderKey: %w", err)
	}
	r, err := newReaderSession(key, de, nullHandover)
	if err != nil {
		return nil, err
	}
	if !r.engagement.ble {
		return nil, fmt.Errorf("proximity: DeviceEngagement offers no BLE retrieval method")
	}
	r.readerAuth = cfg.readerAuth
	return r, nil
}

// newReaderSession is the engagement-independent constructor, as for
// newDeviceSession.
func newReaderSession(key *ecdsa.PrivateKey, deviceEngagement []byte, handover cbor.RawMessage) (*ReaderSession, error) {
	pe, err := parseDeviceEngagement(deviceEngagement)
	if err != nil {
		return nil, err
	}
	eReaderKeyBytes, err := encodeCoseKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	transcript, err := buildSessionTranscriptBytes(deviceEngagement, eReaderKeyBytes, handover)
	if err != nil {
		return nil, err
	}
	cs, err := newSessionCipher(key, pe.eDeviceKey, transcript, true)
	if err != nil {
		return nil, err
	}
	return &ReaderSession{
		eReaderKey: key, eReaderKeyBytes: eReaderKeyBytes, engagement: pe,
		sessionTranscriptBytes: transcript, cipher: cs,
	}, nil
}

// ServiceUUID is the BLE service UUID from the mdoc's engagement, in
// 8-4-4-4-12 form.
func (r *ReaderSession) ServiceUUID() string { return formatUUID(r.engagement.uuid) }

// BLEMode is the BLE mode the mdoc's engagement offers: with
// PeripheralServer the reader scans for ServiceUUID as central; with
// CentralClient it advertises it as peripheral.
func (r *ReaderSession) BLEMode() BLEMode { return r.engagement.bleMode }

// BLEIdent is the value to serve on the Ident characteristic in mdoc
// central client mode (§8.3.3.1.1), where the reader is the GATT
// server. Peripheral server mode doesn't use it.
func (r *ReaderSession) BLEIdent() []byte { return bleIdent(r.engagement.eDeviceKeyBytes) }

// SessionTranscriptBytes is §9.1.5.1's SessionTranscriptBytes, which
// the mdoc's device authentication covers.
func (r *ReaderSession) SessionTranscriptBytes() []byte { return r.sessionTranscriptBytes }

// Establishment builds the reader's first message (§9.1.1.4): a
// SessionEstablishment carrying EReaderKey and the encrypted
// DeviceRequest for docType and elements (namespace → element
// identifiers). Verify then accepts only these elements back.
func (r *ReaderSession) Establishment(docType string, elements map[string][]string) ([]byte, error) {
	if r.closed {
		return nil, ErrSessionClosed
	}
	if r.sent {
		return nil, fmt.Errorf("proximity: SessionEstablishment already sent")
	}
	if r.readerAuth != nil {
		return nil, fmt.Errorf("proximity: reader authentication is not supported yet")
	}
	req, err := encodeDeviceRequest(docType, elements)
	if err != nil {
		return nil, err
	}
	msg, err := r.establishment(req)
	if err != nil {
		return nil, err
	}
	r.docType, r.requested = docType, newRequestedSet(elements)
	return msg, nil
}

// establishment encrypts deviceRequest into a SessionEstablishment.
func (r *ReaderSession) establishment(deviceRequest []byte) ([]byte, error) {
	ct, err := r.cipher.encrypt(deviceRequest)
	if err != nil {
		return nil, err
	}
	eReaderKeyBytes, err := wrapTag24(r.eReaderKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("proximity: encode EReaderKeyBytes: %w", err)
	}
	msg, err := encMode.Marshal(sessionEstablishment{EReaderKey: eReaderKeyBytes, Data: ct})
	if err != nil {
		return nil, fmt.Errorf("proximity: encode SessionEstablishment: %w", err)
	}
	r.sent = true
	return msg, nil
}

// Verified is a verified proximity presentation.
type Verified struct {
	DocType string

	// Claims are the disclosed issuer-signed elements: namespace →
	// element identifier → value, as credential/mdoc decodes them.
	Claims map[string]map[string]interface{}

	// DeviceSignedClaims are any device-signed elements (§8.3.2.1.2.2),
	// nil when there are none.
	DeviceSignedClaims map[string]map[string]interface{}

	// IssuerCN is the document signer certificate's subject common
	// name; TrustAnchorCN is the common name of the root in roots its
	// chain verified to.
	IssuerCN      string
	TrustAnchorCN string

	ValidFrom  time.Time
	ValidUntil time.Time

	// DeviceAuth is how the mdoc authenticated: DeviceAuthSignature or
	// DeviceAuthMAC.
	DeviceAuth mdoc.DeviceAuthType
}

// Verify decrypts the mdoc's reply and verifies the DeviceResponse in
// it, at now (zero means the current time):
//
//   - the issuer's certificate chain (IssuerAuth's x5chain) verifies to
//     a root in roots;
//   - the document's docType is the one requested, and the MSO's;
//   - credential/mdoc.Verify passes: issuer signature, value digests,
//     validity;
//   - device authentication — signature or MAC — verifies against the
//     MSO's device key over this session's transcript, and any
//     device-signed elements are within the MSO's key authorizations;
//   - every returned element was requested.
//
// A reply carrying only status 20 is ErrDeclined; a DeviceResponse with
// no documents is ErrNoDocument. Errors that wrap ErrSessionEncryption
// or ErrCBORDecoding have a status reply (StatusFor). Any reply ends
// the session, since this reader sends one request.
func (r *ReaderSession) Verify(msg []byte, roots *x509.CertPool, now time.Time) (Verified, error) {
	if r.closed {
		return Verified{}, ErrSessionClosed
	}
	if !r.sent {
		return Verified{}, fmt.Errorf("proximity: no request sent")
	}
	r.closed = true
	if now.IsZero() {
		now = time.Now()
	}

	data, status, err := receive(r.cipher, msg)
	if err != nil {
		return Verified{}, err
	}
	if data == nil {
		if *status == StatusSessionTermination {
			return Verified{}, ErrDeclined
		}
		return Verified{}, fmt.Errorf("proximity: mdoc ended the session with status %d", *status)
	}
	doc, err := parseDeviceResponse(data)
	if err != nil {
		return Verified{}, err
	}
	return r.verifyDocument(doc, roots, now)
}

func (r *ReaderSession) verifyDocument(doc responseDocument, roots *x509.CertPool, now time.Time) (Verified, error) {
	if doc.docType != r.docType {
		return Verified{}, fmt.Errorf("proximity: document docType %q, requested %q", doc.docType, r.docType)
	}

	protected, unprotected, _, err := cose.DecodeUnverifiedMax(doc.issuerSigned.IssuerAuth, MaxMessageBytes)
	if err != nil {
		return Verified{}, fmt.Errorf("proximity: decode IssuerAuth: %w", err)
	}
	// x5chain is an unprotected header in mdoc (as Multipaz reads it).
	chain := unprotected.X5Chain
	if len(chain) == 0 {
		return Verified{}, fmt.Errorf("proximity: IssuerAuth has no x5chain")
	}
	leaf, chains, err := certchain.VerifyChainsAt(chain, roots, now)
	if err != nil {
		return Verified{}, fmt.Errorf("proximity: issuer certificate: %w", err)
	}
	if err := checkIACASubject(chains); err != nil {
		return Verified{}, err
	}
	verified, err := mdoc.Verify(doc.issuerSigned, r.docType, leaf.PublicKey, protected.Alg, mdoc.VerifyOptions{
		Now: func() time.Time { return now },
	})
	if err != nil {
		return Verified{}, fmt.Errorf("proximity: %w", err)
	}
	// §9.3.1 step 5: the MSO's signed date is within the document
	// signer certificate's validity.
	if signed := verified.ValidityInfo.Signed; signed.Before(leaf.NotBefore) || signed.After(leaf.NotAfter) {
		return Verified{}, fmt.Errorf("proximity: MSO signed %s, outside the document signer certificate's validity", signed.Format(time.RFC3339))
	}

	switch doc.deviceSigned.AuthType {
	case mdoc.DeviceAuthSignature:
		alg, err := deviceAuthAlg(verified.DeviceKey)
		if err != nil {
			return Verified{}, fmt.Errorf("proximity: MSO device key: %w", err)
		}
		if err := mdoc.VerifyDeviceSignature(doc.deviceSigned, verified.DeviceKey, alg, r.sessionTranscriptBytes, r.docType); err != nil {
			return Verified{}, fmt.Errorf("proximity: %w", err)
		}
	case mdoc.DeviceAuthMAC:
		deviceKey, ok := verified.DeviceKey.(*ecdsa.PublicKey)
		if !ok {
			return Verified{}, fmt.Errorf("proximity: DeviceMAC needs a P-256 device key, the MSO has %T", verified.DeviceKey)
		}
		if err := mdoc.VerifyDeviceMAC(doc.deviceSigned, deviceKey, r.eReaderKey, r.sessionTranscriptBytes, r.docType); err != nil {
			return Verified{}, fmt.Errorf("proximity: %w", err)
		}
	default:
		return Verified{}, fmt.Errorf("proximity: unknown device authentication type %d", doc.deviceSigned.AuthType)
	}
	if err := mdoc.CheckKeyAuthorizations(doc.deviceSigned.NameSpaces, verified.KeyAuthorizations); err != nil {
		return Verified{}, fmt.Errorf("proximity: %w", err)
	}

	if extra := r.requested.unrequested(verified.NameSpaces); len(extra) > 0 {
		return Verified{}, fmt.Errorf("proximity: response carries unrequested elements %v", extra)
	}
	if extra := r.requested.unrequested(doc.deviceSigned.NameSpaces); len(extra) > 0 {
		return Verified{}, fmt.Errorf("proximity: response carries unrequested device-signed elements %v", extra)
	}

	out := Verified{
		DocType:    verified.DocType,
		Claims:     verified.NameSpaces,
		IssuerCN:   leaf.Subject.CommonName,
		ValidFrom:  verified.ValidityInfo.ValidFrom,
		ValidUntil: verified.ValidityInfo.ValidUntil,
		DeviceAuth: doc.deviceSigned.AuthType,
	}
	if len(doc.deviceSigned.NameSpaces) > 0 {
		out.DeviceSignedClaims = doc.deviceSigned.NameSpaces
	}
	if len(chains) > 0 && len(chains[0]) > 0 {
		out.TrustAnchorCN = chains[0][len(chains[0])-1].Subject.CommonName
	}
	return out, nil
}

// Termination builds a SessionData carrying only status 20 and closes
// the session.
func (r *ReaderSession) Termination() []byte {
	r.closed = true
	return StatusMessage(StatusSessionTermination)
}

// checkIACASubject applies §9.3.3's checks on top of RFC 5280 path
// validation: on some verified path, the trust anchor's countryName
// equals the document signer's, and so does stateOrProvinceName when
// both certificates carry one.
func checkIACASubject(chains [][]*x509.Certificate) error {
	var lastErr error
	for _, chain := range chains {
		leaf, root := chain[0], chain[len(chain)-1]
		if !slices.Equal(root.Subject.Country, leaf.Subject.Country) {
			lastErr = fmt.Errorf("proximity: document signer countryName %v differs from its IACA's %v", leaf.Subject.Country, root.Subject.Country)
			continue
		}
		if len(root.Subject.Province) > 0 && len(leaf.Subject.Province) > 0 && !slices.Equal(root.Subject.Province, leaf.Subject.Province) {
			lastErr = fmt.Errorf("proximity: document signer stateOrProvinceName %v differs from its IACA's %v", leaf.Subject.Province, root.Subject.Province)
			continue
		}
		return nil
	}
	return lastErr
}
