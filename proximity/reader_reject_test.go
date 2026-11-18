package proximity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
)

// In mdoc peripheral server mode the reader connects to whichever device
// advertises the holder's service UUID, which the holder's adverts carry
// in the clear. TryVerifyDocuments rejects a reply that doesn't show its
// sender holds the session's keys — junk, or a bare status, which isn't
// encrypted — and leaves the session waiting: the genuine holder, sent
// the same SessionEstablishment, then answers and verifies.
func TestTryVerifyDocuments_RejectsRepliesNotFromTheHolder(t *testing.T) {
	fx := issueFixture(t, mDL)
	elements := map[string][]string{mDLNS: {"age_over_18"}}
	junk := make([]byte, 64)
	if _, err := rand.Read(junk); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		reply    []byte
		why      error
		declined bool
	}{
		{"junk ciphertext", mustMarshal(t, sessionData{Data: junk}), ErrSessionEncryption, false},
		{"not CBOR", []byte{0x01}, ErrCBORDecoding, false},
		{"bare status 20", StatusMessage(StatusSessionTermination), ErrDeclined, true},
		{"bare status 10", StatusMessage(StatusSessionEncryptionError), ErrResponseRejected, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			holder, err := NewDeviceSession(nil)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewReaderSession(holder.QRCode(), devReader()...)
			if err != nil {
				t.Fatal(err)
			}
			if reader.BLEMode() != PeripheralServer {
				t.Fatalf("reader mode %v", reader.BLEMode())
			}
			est, err := reader.Establishment(mDL, elements)
			if err != nil {
				t.Fatal(err)
			}

			// However many impostors answer first: a limit would let
			// devices that never saw the engagement end the session.
			for range 100 {
				_, err := reader.TryVerifyDocuments(context.Background(), tc.reply, fx.roots, time.Now())
				if !errors.Is(err, ErrResponseRejected) || !errors.Is(err, tc.why) {
					t.Fatalf("impostor reply: %v, want ErrResponseRejected wrapping %v", err, tc.why)
				}
				if errors.Is(err, ErrDeclined) != tc.declined {
					t.Fatalf("impostor reply: %v, declined %v", err, !tc.declined)
				}
				if _, ok := StatusFor(err); ok {
					t.Fatal("a rejected reply has a status to send")
				}
			}

			// The genuine holder, sent the same SessionEstablishment.
			reqBytes, err := holder.TrySessionEstablishment(est)
			if err != nil {
				t.Fatalf("holder: %v", err)
			}
			reqs, err := ParseDeviceRequest(reqBytes)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := buildDeviceResponse(fx.issuerSigned, fx.docType, fx.deviceKey, holder.SessionTranscriptBytes(), reqs[0].Elements)
			if err != nil {
				t.Fatal(err)
			}
			genuine, err := holder.Encrypt(resp, true)
			if err != nil {
				t.Fatal(err)
			}
			vs, err := reader.TryVerifyDocuments(context.Background(), genuine, fx.roots, time.Now())
			if err != nil {
				t.Fatalf("the holder's reply after rejected ones: %v", err)
			}
			if len(vs) != 1 || vs[0].Claims[mDLNS]["age_over_18"] != true {
				t.Fatalf("verified %+v", vs)
			}
			// A reply that decrypted ends the session.
			if _, err := reader.TryVerifyDocuments(context.Background(), genuine, fx.roots, time.Now()); !errors.Is(err, ErrSessionClosed) {
				t.Fatalf("after the holder's reply: %v, want ErrSessionClosed", err)
			}
		})
	}
}

// A reply that decrypts but doesn't verify proves its sender held the
// session's keys: TryVerify ends the session on it, as Verify does,
// rather than wait for another. Verify itself still ends the session on
// any reply, a bare status 20 being ErrDeclined.
func TestTryVerify_EndsOnADecryptedReply(t *testing.T) {
	fx := issueFixture(t, mDL)
	holder, err := NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewReaderSession(holder.QRCode(), devReader()...)
	if err != nil {
		t.Fatal(err)
	}
	est, err := reader.Establishment(mDL, map[string][]string{mDLNS: {"age_over_18"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.TrySessionEstablishment(est); err != nil {
		t.Fatal(err)
	}
	notAResponse, err := holder.Encrypt([]byte{0xa0}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.TryVerify(context.Background(), notAResponse, fx.roots, time.Now()); err == nil || errors.Is(err, ErrResponseRejected) {
		t.Fatalf("a decrypted reply that isn't a DeviceResponse: %v, want a failure that isn't a rejection", err)
	}
	if _, err := reader.TryVerify(context.Background(), notAResponse, fx.roots, time.Now()); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("after it: %v, want ErrSessionClosed", err)
	}

	holder, err = NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	reader, err = NewReaderSession(holder.QRCode(), devReader()...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Establishment(mDL, map[string][]string{mDLNS: {"age_over_18"}}); err != nil {
		t.Fatal(err)
	}
	_, err = reader.Verify(context.Background(), StatusMessage(StatusSessionTermination), fx.roots, time.Now())
	if !errors.Is(err, ErrDeclined) || errors.Is(err, ErrResponseRejected) {
		t.Fatalf("Verify of a bare status 20: %v, want ErrDeclined", err)
	}
	if _, err := reader.TryVerify(context.Background(), StatusMessage(StatusSessionTermination), fx.roots, time.Now()); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("after Verify: %v, want ErrSessionClosed", err)
	}
}

// A reader that scanned the QR code chooses EReaderKeyBytes' encoding,
// and the holder's device key signs a SessionTranscript carrying it as
// sent (§9.1.5.1). The holder takes no more than MaxEReaderKeyBytes, and
// only the parameters an ephemeral key has, so the reader can't put a
// statement of its own under the holder's signature; kid and alg are
// taken.
func TestTrySessionEstablishment_RefusesReaderChosenKeyParameters(t *testing.T) {
	readerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := mdoc.NewCoseKey(&readerKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	statement := bytes.Repeat([]byte("I, the holder, agree to pay 1000 EUR. "), 64<<10/38)
	for _, tc := range []struct {
		name   string
		key    map[any]any
		refuse bool
	}{
		{"kty crv x y", map[any]any{1: ck.Kty, -1: ck.Crv, -2: ck.X, -3: ck.Y}, false},
		{"with kid and alg", map[any]any{1: ck.Kty, 2: []byte("reader-1"), 3: -25, -1: ck.Crv, -2: ck.X, -3: ck.Y}, false},
		{"a private parameter", map[any]any{1: ck.Kty, -1: ck.Crv, -2: ck.X, -3: ck.Y, -65537: statement}, true},
		{"a short private parameter", map[any]any{1: ck.Kty, -1: ck.Crv, -2: ck.X, -3: ck.Y, -65537: []byte("hi")}, true},
		{"a text label", map[any]any{1: ck.Kty, -1: ck.Crv, -2: ck.X, -3: ck.Y, "note": "hi"}, true},
		{"key_ops", map[any]any{1: ck.Kty, 4: []int{7}, -1: ck.Crv, -2: ck.X, -3: ck.Y}, true},
		{"an oversized kid", map[any]any{1: ck.Kty, 2: statement[:MaxEReaderKeyBytes], -1: ck.Crv, -2: ck.X, -3: ck.Y}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			holder, err := NewDeviceSession(nil)
			if err != nil {
				t.Fatal(err)
			}
			pe, err := parseDeviceEngagement(holder.DeviceEngagementBytes())
			if err != nil {
				t.Fatal(err)
			}
			eReaderKeyBytes := mustMarshal(t, tc.key)
			transcript, err := buildSessionTranscriptBytes(holder.DeviceEngagementBytes(), eReaderKeyBytes, nullHandover)
			if err != nil {
				t.Fatal(err)
			}
			cs, err := newSessionCipher(readerKey, pe.eDeviceKey, transcript, true)
			if err != nil {
				t.Fatal(err)
			}
			req, err := encodeDeviceRequest(mDL, map[string][]string{mDLNS: {"age_over_18"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			ct, err := cs.encrypt(req)
			if err != nil {
				t.Fatal(err)
			}
			tagged, err := wrapTag24(eReaderKeyBytes)
			if err != nil {
				t.Fatal(err)
			}
			est := mustMarshal(t, sessionEstablishment{EReaderKey: cbor.RawMessage(tagged), Data: ct})

			_, err = holder.TrySessionEstablishment(est)
			if !tc.refuse {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrEstablishmentRejected) || !errors.Is(err, ErrCBORDecoding) {
				t.Fatalf("taken: %v, want ErrEstablishmentRejected wrapping ErrCBORDecoding", err)
			}
			if holder.SessionTranscriptBytes() != nil {
				t.Fatal("a refused key's transcript was kept")
			}
		})
	}
}
