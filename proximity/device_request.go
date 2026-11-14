package proximity

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"

	"github.com/idfoundry/oid4vcgo/internal/readerauth"
)

// DeviceRequest is a whole DeviceRequest (§8.3.2.1.2.1), as
// DecodeDeviceRequest decodes it: its document requests, its
// second-edition request information, and the reader signatures over
// them, kept as received for VerifyDeviceRequest. It is immutable and
// owns its data: what its accessors return are copies, and changing
// them, or the bytes it was decoded from, changes neither what it
// reports nor what VerifyDeviceRequest checks. Only DecodeDeviceRequest
// makes a usable one; the zero value never authenticates.
type DeviceRequest struct {
	decoded bool
	docs    []DocRequest
	// info is the decoded deviceRequestInfo, Signed false; nil when the
	// request has none. infoBytes is it as received, #6.24(bstr), for
	// ReaderAuthenticationAll.
	info      *RequestInfo
	infoBytes []byte
	// readerAuthAll are the whole-request signatures as received; nil
	// when the request has none.
	readerAuthAll [][]byte
}

// DocRequests are the request's document requests, in its order: a
// copy, down to every slice, map and byte string.
func (r *DeviceRequest) DocRequests() []DocRequest {
	if r == nil || !r.decoded {
		return nil
	}
	return cloneDocRequests(r.docs)
}

// RequestInfo is the request's deviceRequestInfo, decoded, or nil when
// it carries none: a copy, down to every slice and map. Its Signed is
// always false here, since decoding verifies nothing: VerifyDeviceRequest
// reports whether a signature covers it.
func (r *DeviceRequest) RequestInfo() *RequestInfo {
	if r == nil || !r.decoded {
		return nil
	}
	return r.info.clone()
}

func cloneDocRequests(docs []DocRequest) []DocRequest {
	out := make([]DocRequest, len(docs))
	for i, d := range docs {
		out[i] = DocRequest{
			DocType:           d.DocType,
			Elements:          append([][2]string(nil), d.Elements...),
			IntentToRetain:    maps.Clone(d.IntentToRetain),
			ItemsRequestBytes: bytes.Clone(d.ItemsRequestBytes),
			ReaderAuth:        bytes.Clone(d.ReaderAuth),
		}
	}
	return out
}

// RequestAuthentication is VerifyDeviceRequest's result.
type RequestAuthentication struct {
	// Reader is who sent the request, taking every signature it carries
	// into account (VerifyDeviceRequest).
	Reader ReaderAuthentication
	// RequestInfoSigned reports whether a verified whole-request
	// signature covers the request's information: it carries
	// deviceRequestInfo and at least one readerAuthAll, and every
	// signature it carries verified. It is independent of whether the
	// signer is trusted, and never set by per-document signatures.
	RequestInfoSigned bool
}

// VerifyDeviceRequest is the package's VerifyDeviceRequest for this
// session. Call it after HandleSessionEstablishment, before the consent
// prompt, which shows the result.
func (s *DeviceSession) VerifyDeviceRequest(req *DeviceRequest, t ReaderTrust) RequestAuthentication {
	return VerifyDeviceRequest(req, s.sessionTranscriptBytes, t)
}

// VerifyDeviceRequest checks every reader signature req carries over
// the session whose SessionTranscriptBytes is sessionTranscriptBytes:
// each readerAuthAll over ReaderAuthenticationAll (the transcript, every
// ItemsRequestBytes in order, and the deviceRequestInfo as received)
// and each DocRequest's readerAuth over its ReaderAuthentication.
//
// Every signature must verify, by the key of the certificate it
// carries: one that doesn't, or is malformed, makes the reader
// ReaderInvalid, with no chain, an error naming it, and no coverage —
// even when another would verify. A DocRequest without a readerAuth is
// not invalid: a readerAuthAll covers it.
//
// With readerAuthAll, only its signers can be the reader: the first, in
// the request's order, whose chain t trusts is ReaderTrusted; if none
// is, the reader is ReaderUntrusted, with the first signer's chain and
// why t refuses it. A trusted per-document signer doesn't stand in for
// an untrusted whole-request one. Without readerAuthAll, every
// DocRequest counts: the reader is trusted only when one trusted
// certificate signs them all, and otherwise is the weakest DocRequest's
// result (invalid, then unauthenticated, then untrusted), as when each
// is checked with VerifyReaderAuth. A request with no signature is
// ReaderUnauthenticated.
//
// Verification depends only on req, the transcript and t: it changes
// none of them, and calling it again with other roots or another time
// gives that call's own result.
func VerifyDeviceRequest(req *DeviceRequest, sessionTranscriptBytes []byte, t ReaderTrust) RequestAuthentication {
	if req == nil || !req.decoded {
		return invalidRequest(errors.New("proximity: not a DeviceRequest from DecodeDeviceRequest"))
	}
	if len(req.readerAuthAll) == 0 {
		return RequestAuthentication{Reader: documentReader(req.docs, sessionTranscriptBytes, t)}
	}
	transcript, err := sessionTranscript(sessionTranscriptBytes)
	if err != nil {
		return invalidRequest(err)
	}

	items := make([][]byte, len(req.docs))
	for i, d := range req.docs {
		items[i] = d.ItemsRequestBytes
	}
	all, err := readerauth.AuthenticationAllBytes(transcript, items, req.infoBytes)
	if err != nil {
		return invalidRequest(fmt.Errorf("proximity: %w", err))
	}
	type signer struct {
		ders  [][]byte
		chain []*x509.Certificate
	}
	signers := make([]signer, 0, len(req.readerAuthAll))
	for i, sig := range req.readerAuthAll {
		ders, chain, err := verifySignature(sig, all)
		if err != nil {
			return invalidRequest(fmt.Errorf("readerAuthAll[%d]: %w", i, err))
		}
		signers = append(signers, signer{ders, chain})
	}
	for i, d := range req.docs {
		if len(d.ReaderAuth) == 0 {
			continue
		}
		detached, err := readerauth.AuthenticationBytes(transcript, d.ItemsRequestBytes)
		if err != nil {
			return invalidRequest(fmt.Errorf("docRequests[%d]: %w", i, err))
		}
		if _, _, err := verifySignature(d.ReaderAuth, detached); err != nil {
			return invalidRequest(fmt.Errorf("docRequests[%d] readerAuth: %w", i, err))
		}
	}

	// Every signature verified: the whole-request signers are the
	// candidates, in order.
	signed := req.info != nil
	var firstErr error
	for i, s := range signers {
		if _, err := readerauth.VerifyTrust(s.ders, t.internal()); err != nil {
			if i == 0 {
				firstErr = err
			}
			continue
		}
		return RequestAuthentication{Reader: ReaderAuthentication{Status: ReaderTrusted, Chain: s.chain}, RequestInfoSigned: signed}
	}
	return RequestAuthentication{
		Reader:            ReaderAuthentication{Status: ReaderUntrusted, Chain: signers[0].chain, Err: firstErr},
		RequestInfoSigned: signed,
	}
}

// verifySignature checks sig, a reader COSE_Sign1, over detached by the
// key of the leaf of the chain it carries, and returns that chain.
func verifySignature(sig, detached []byte) ([][]byte, []*x509.Certificate, error) {
	ders, chain, err := readerauth.Chain(sig)
	if err != nil {
		return nil, nil, err
	}
	if err := readerauth.VerifySignature(sig, detached, chain[0]); err != nil {
		return nil, nil, err
	}
	return ders, chain, nil
}

func invalidRequest(err error) RequestAuthentication {
	return RequestAuthentication{Reader: ReaderAuthentication{Status: ReaderInvalid, Err: err}}
}

// readerWeakness orders statuses from strongest to weakest, for
// documentReader.
var readerWeakness = map[ReaderStatus]int{
	ReaderTrusted: 0, ReaderUntrusted: 1, ReaderUnauthenticated: 2, ReaderInvalid: 3,
}

// documentReader is who sent a request signed only per document: trusted
// only when every DocRequest is signed by the same trusted reader.
// Otherwise it's the weakest DocRequest's result (invalid, then
// unauthenticated, then untrusted): a reader can't attach an unsigned or
// untrusted request for one document to a trusted one for another and
// have the wallet show the trusted name for both.
func documentReader(docs []DocRequest, sessionTranscriptBytes []byte, t ReaderTrust) ReaderAuthentication {
	var reader ReaderAuthentication
	for i, d := range docs {
		got := VerifyReaderAuth(d, sessionTranscriptBytes, t)
		if i > 0 && got.Status == ReaderTrusted && reader.Status == ReaderTrusted && !got.Chain[0].Equal(reader.Chain[0]) {
			got = ReaderAuthentication{Status: ReaderUntrusted, Chain: got.Chain, Err: errors.New("the documents are signed by different readers")}
		}
		if i == 0 || readerWeakness[got.Status] > readerWeakness[reader.Status] {
			reader = got
		}
	}
	return reader
}
