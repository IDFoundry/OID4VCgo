package walletflow_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// The three document types the test issuer issues, and each one's
// namespace, in the order the readers here ask for them.
var (
	multiDocTypes   = []string{walletflowtest.DocType, walletflowtest.DocType2, walletflowtest.DocType3}
	multiNameSpaces = []string{walletflowtest.NameSpace, walletflowtest.NameSpace2, walletflowtest.NameSpace3}
)

// holderKeys is a MemoryKeyStore whose keys, once armed, count their
// signatures, and can fail or block one of them — a holder cancelling
// or still looking at that key's prompt — or agree keys only once.
type holderKeys struct {
	*walletflow.MemoryKeyStore
	armed   atomic.Bool
	signed  atomic.Int32
	failAt  int32 // the signature to fail, from 1; 0 for none
	blockAt int32 // the signature to block until release, from 1; 0 for none
	signing chan struct{}
	release chan struct{}
	// agreeOnce has the first Agree succeed and every later one fail
	// with proximity.ErrNoKeyAgreement.
	agreeOnce bool
	agreed    atomic.Int32
}

type holderKey struct {
	walletflow.Key
	s *holderKeys
}

func newHolderKeys(f fixture) *holderKeys {
	return &holderKeys{MemoryKeyStore: f.keys, signing: make(chan struct{}, 1), release: make(chan struct{})}
}

func (s *holderKeys) NewKey(ctx context.Context, p walletflow.KeyPurpose) (walletflow.Key, error) {
	k, err := s.MemoryKeyStore.NewKey(ctx, p)
	return holderKey{k, s}, err
}

func (s *holderKeys) Key(ctx context.Context, id string) (walletflow.Key, error) {
	k, err := s.MemoryKeyStore.Key(ctx, id)
	if err != nil {
		return nil, err
	}
	return holderKey{k, s}, nil
}

var errCancelled = errors.New("test key: the holder cancelled")

func (k holderKey) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	if k.s.armed.Load() {
		n := k.s.signed.Add(1)
		if n == k.s.failAt {
			return nil, errCancelled
		}
		if n == k.s.blockAt {
			k.s.signing <- struct{}{}
			<-k.s.release
		}
	}
	return k.Key.Sign(r, d, o)
}

func (k holderKey) Agree(peer *ecdsa.PublicKey) ([]byte, error) {
	if !k.s.agreeOnce || k.s.agreed.Add(1) > 1 {
		return nil, fmt.Errorf("test key: %w", proximity.ErrNoKeyAgreement)
	}
	priv, err := k.Key.(ecdhKey).ECDH()
	if err != nil {
		return nil, err
	}
	pub, err := peer.ECDH()
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

func multiWallet(t *testing.T, f fixture, keys walletflow.KeyStore, auth walletflow.ProximityDeviceAuth, readerRoots ...*mdocReader) *walletflow.Wallet {
	t.Helper()
	cfg := walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
		Development: true, ProximityDeviceAuth: auth,
	}
	if len(readerRoots) > 0 {
		cfg.MdocReaderRoots = readerRoots[0].roots
	}
	w, err := walletflow.New(cfg, walletflow.Dependencies{Keys: keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// receiveThree receives an mdoc of each of multiDocTypes, returning
// their IDs in that order.
func receiveThree(t *testing.T, f fixture, w *walletflow.Wallet) []string {
	t.Helper()
	held := receive(t, f, w, walletflowtest.MdocConfigurationID, walletflowtest.MdocConfigurationID2, walletflowtest.MdocConfigurationID3)
	ids := make([]string, len(multiDocTypes))
	for _, c := range held {
		if i := slices.Index(multiDocTypes, c.DocType); i >= 0 {
			ids[i] = c.ID
		}
	}
	for i, id := range ids {
		if id == "" {
			t.Fatalf("no %s mdoc received", multiDocTypes[i])
		}
	}
	return ids
}

// askThree starts a presentation and has an unsigned reader ask for
// family_name and given_name from each of multiDocTypes.
func askThree(t *testing.T, w *walletflow.Wallet) (*walletflow.ProximityPresentation, *proximity.ReaderSession) {
	t.Helper()
	p, err := w.StartProximityPresentation()
	if err != nil {
		t.Fatal(err)
	}
	r, err := proximity.NewReaderSession(p.QRCode(), proximity.WithAssurance(verifier.AssuranceDevelopment), proximity.WithIssuerRevocation(certrevocation.NoCheck{}))
	if err != nil {
		t.Fatal(err)
	}
	var docs []proximity.DocumentRequest
	for i, dt := range multiDocTypes {
		docs = append(docs, proximity.DocumentRequest{DocType: dt, Elements: map[string][]string{multiNameSpaces[i]: {"family_name", "given_name"}}})
	}
	msg, err := r.EstablishmentDocuments(docs)
	if err != nil {
		t.Fatal(err)
	}
	if ev := p.HandleMessage(context.Background(), msg); !ev.Request {
		t.Fatalf("event %+v", ev)
	}
	if got := p.Requests(); len(got) != 3 {
		t.Fatalf("%d requests, want 3", len(got))
	}
	return p, r
}

// answer is request number i answered with ids[i], disclosing its
// family_name.
func answer(ids []string, i int) walletflow.MdocAnswer {
	return walletflow.MdocAnswer{Request: i, CredentialID: ids[i], Elements: [][2]string{{multiNameSpaces[i], "family_name"}}}
}

// checkVerified checks vs are the documents of requests answered, in
// the request's order, each disclosing only family_name.
func checkVerified(t *testing.T, vs []proximity.Verified, answered []int) {
	t.Helper()
	if len(vs) != len(answered) {
		t.Fatalf("%d documents verified, want %d", len(vs), len(answered))
	}
	for n, i := range answered {
		if vs[n].DocType != multiDocTypes[i] {
			t.Errorf("document %d is %q, want %q", n, vs[n].DocType, multiDocTypes[i])
		}
		if got := vs[n].Claims[multiNameSpaces[i]]; len(vs[n].Claims) != 1 || len(got) != 1 || got["family_name"] != walletflowtest.FamilyName {
			t.Errorf("%s disclosed %v, want only family_name", vs[n].DocType, vs[n].Claims)
		}
	}
}

// A reader asking for three documents gets one DeviceResponse with the
// ones the holder answers — all three, two or one — in the request's
// order whatever order the holder gave them in, each verified.
func TestProximityRespondDocuments(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 3})
	w := multiWallet(t, f, f.keys, walletflow.ProximityDeviceSignature)
	ids := receiveThree(t, f, w)
	ctx := context.Background()
	for _, answered := range [][]int{{0, 1, 2}, {0, 2}, {1}} {
		t.Run(fmt.Sprint(answered), func(t *testing.T) {
			p, r := askThree(t, w)
			var answers []walletflow.MdocAnswer
			for _, i := range slices.Backward(answered) {
				answers = append(answers, answer(ids, i))
			}
			presented, err := p.RespondDocuments(ctx, answers)
			if err != nil {
				t.Fatal(err)
			}
			if presented.Linkable || presented.LinkableCredentials != nil {
				t.Errorf("Linkable %v %v for unused copies", presented.Linkable, presented.LinkableCredentials)
			}
			vs, err := r.VerifyDocuments(ctx, presented.Send, f.env.IssuerRoots, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			checkVerified(t, vs, answered)
			if _, err := p.RespondDocuments(ctx, answers); !errors.Is(err, walletflow.ErrWrongStep) {
				t.Errorf("a second RespondDocuments: %v", err)
			}
		})
	}
}

// Respond, one answer, still gives the one-document response a
// one-document reader verifies.
func TestProximityRespond_OneDocumentUnchanged(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	w := multiWallet(t, f, f.keys, walletflow.ProximityDeviceSignature)
	id := heldMdoc(t, receive(t, f, w, walletflowtest.MdocConfigurationID))
	p, err := w.StartProximityPresentation()
	if err != nil {
		t.Fatal(err)
	}
	r, msg := proximityRequest(t, p, nil)
	if !p.HandleMessage(context.Background(), msg).Request {
		t.Fatal("no request")
	}
	presented, err := p.Respond(context.Background(), 0, id, familyName())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Verify(context.Background(), presented.Send, f.env.IssuerRoots, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// RespondDocuments refuses an answer Respond would, no answer, and a
// request answered twice, sending nothing: the request stands, and a
// good answer then goes through.
func TestProximityRespondDocuments_Refuses(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	w := multiWallet(t, f, f.keys, walletflow.ProximityDeviceSignature)
	ids := receiveThree(t, f, w)
	ctx := context.Background()
	p, r := askThree(t, w)
	for name, answers := range map[string][]walletflow.MdocAnswer{
		"none":               nil,
		"answered twice":     {answer(ids, 0), answer(ids, 0)},
		"out of range":       {answer(ids, 0), {Request: 3, CredentialID: ids[0], Elements: [][2]string{{walletflowtest.NameSpace, "family_name"}}}},
		"another doctype":    {answer(ids, 0), {Request: 1, CredentialID: ids[2], Elements: [][2]string{{walletflowtest.NameSpace2, "family_name"}}}},
		"unrequested":        {answer(ids, 0), {Request: 1, CredentialID: ids[1], Elements: [][2]string{{walletflowtest.NameSpace2, "portrait"}}}},
		"no element":         {answer(ids, 0), {Request: 1, CredentialID: ids[1]}},
		"unknown credential": {{Request: 0, CredentialID: "nope", Elements: [][2]string{{walletflowtest.NameSpace, "family_name"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.RespondDocuments(ctx, answers); !errors.Is(err, walletflow.ErrInvalidSelection) {
				t.Fatalf("RespondDocuments = %v, want ErrInvalidSelection", err)
			}
		})
	}
	for _, id := range ids {
		stored, err := f.store.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		for _, cp := range stored.AllCopies() {
			if cp.Presented || len(cp.ShownTo) != 0 {
				t.Fatalf("a refused answer marked %s's copy %+v", id, cp)
			}
		}
	}
	presented, err := p.RespondDocuments(ctx, []walletflow.MdocAnswer{answer(ids, 0), answer(ids, 1)})
	if err != nil {
		t.Fatal(err)
	}
	vs, err := r.VerifyDocuments(ctx, presented.Send, f.env.IssuerRoots, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	checkVerified(t, vs, []int{0, 1})
}

// One credential can't answer two requests, whatever they ask for: the
// reader would see one holder key and status entry twice.
func TestOrderAnswers(t *testing.T) {
	a := walletflow.MdocAnswer{Request: 1, CredentialID: "a", Elements: [][2]string{{"ns", "x"}}}
	b := walletflow.MdocAnswer{Request: 0, CredentialID: "b", Elements: [][2]string{{"ns", "x"}}}
	ordered, err := walletflow.OrderAnswers([]walletflow.MdocAnswer{a, b}, "org.example.a", "org.example.b")
	if err != nil || len(ordered) != 2 || ordered[0].Request != 0 || ordered[1].Request != 1 {
		t.Fatalf("OrderAnswers = %+v, %v; want them in the request's order", ordered, err)
	}
	b.CredentialID = "a"
	if _, err := walletflow.OrderAnswers([]walletflow.MdocAnswer{a, b}, "org.example.a", "org.example.b"); !errors.Is(err, walletflow.ErrInvalidSelection) {
		t.Fatalf("one credential for two requests: %v, want ErrInvalidSelection", err)
	}
	// A request (from another reader) asking for one type twice: two
	// credentials of it answer at most one, since a Document names only
	// its docType and this repository's readers refuse two of one type.
	b.CredentialID = "b"
	if _, err := walletflow.OrderAnswers([]walletflow.MdocAnswer{a, b}, "org.iso.18013.5.1.mDL", "org.iso.18013.5.1.mDL"); !errors.Is(err, walletflow.ErrInvalidSelection) {
		t.Fatalf("two requests of one type: %v, want ErrInvalidSelection", err)
	}
	if _, err := walletflow.OrderAnswers([]walletflow.MdocAnswer{a}, "org.iso.18013.5.1.mDL", "org.iso.18013.5.1.mDL"); err != nil {
		t.Fatalf("one of two requests of one type: %v", err)
	}
}

// The holder cancelling the second of three keys' prompts sends
// nothing: no copy is marked presented or shown, the third key isn't
// asked, and the request stands for another try.
func TestProximityRespondDocuments_CancelledPrompt(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 1})
	keys := newHolderKeys(f)
	w := multiWallet(t, f, keys, walletflow.ProximityDeviceSignature)
	ids := receiveThree(t, f, w)
	ctx := context.Background()
	p, r := askThree(t, w)
	keys.failAt = 2
	keys.armed.Store(true)
	all := []walletflow.MdocAnswer{answer(ids, 0), answer(ids, 1), answer(ids, 2)}
	presented, err := p.RespondDocuments(ctx, all)
	if !errors.Is(err, errCancelled) || presented.Send != nil {
		t.Fatalf("RespondDocuments = %v, Send %x; want the key's error and nothing to send", err, presented.Send)
	}
	if n := keys.signed.Load(); n != 2 {
		t.Errorf("%d keys asked, want 2: none after the cancelled one", n)
	}
	for _, id := range ids {
		stored, err := f.store.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if cp := stored.AllCopies()[0]; cp.Presented || len(cp.ShownTo) != 0 {
			t.Errorf("after a cancelled prompt %s's copy is %+v", id, cp)
		}
	}
	keys.failAt = 0
	presented, err = p.RespondDocuments(ctx, all)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := r.VerifyDocuments(ctx, presented.Send, f.env.IssuerRoots, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	checkVerified(t, vs, []int{0, 1, 2})
}

// Terminate while the first key's prompt is up ends it there: the
// second key is never asked, and nothing is sent.
func TestProximityRespondDocuments_TerminatedBetweenKeys(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 1})
	keys := newHolderKeys(f)
	w := multiWallet(t, f, keys, walletflow.ProximityDeviceSignature)
	ids := receiveThree(t, f, w)
	ctx := context.Background()
	p, _ := askThree(t, w)
	keys.blockAt = 1
	keys.armed.Store(true)
	type result struct {
		presented walletflow.ProximityPresented
		err       error
	}
	done := make(chan result, 1)
	go func() {
		pr, err := p.RespondDocuments(ctx, []walletflow.MdocAnswer{answer(ids, 0), answer(ids, 1)})
		done <- result{pr, err}
	}()
	<-keys.signing
	go p.Terminate()
	for !walletflow.Terminating(p) {
		runtime.Gosched()
	}
	close(keys.release)
	res := <-done
	if !errors.Is(res.err, walletflow.ErrTerminated) || res.presented.Send != nil {
		t.Fatalf("RespondDocuments after Terminate: %v, Send %x", res.err, res.presented.Send)
	}
	if n := keys.signed.Load(); n != 1 {
		t.Errorf("%d keys asked, want 1", n)
	}
	for _, id := range ids[:2] {
		stored, err := f.store.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if cp := stored.AllCopies()[0]; cp.Presented {
			t.Errorf("after Terminate %s's copy is %+v", id, cp)
		}
	}
}

// Each document authenticates on its own: with
// ProximityDeviceMACPreferred, the first key agrees keys and MACs, and
// the second, which can't, signs.
func TestProximityRespondDocuments_MixedDeviceAuth(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	keys := newHolderKeys(f)
	keys.agreeOnce = true
	w := multiWallet(t, f, keys, walletflow.ProximityDeviceMACPreferred)
	ids := receiveThree(t, f, w)
	ctx := context.Background()
	p, r := askThree(t, w)
	presented, err := p.RespondDocuments(ctx, []walletflow.MdocAnswer{answer(ids, 0), answer(ids, 1)})
	if err != nil {
		t.Fatal(err)
	}
	vs, err := r.VerifyDocuments(ctx, presented.Send, f.env.IssuerRoots, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	checkVerified(t, vs, []int{0, 1})
	if vs[0].DeviceAuth != mdoc.DeviceAuthMAC || vs[1].DeviceAuth != mdoc.DeviceAuthSignature {
		t.Errorf("device auth %v, %v; want MAC, then signature", vs[0].DeviceAuth, vs[1].DeviceAuth)
	}
}

// With one copy each, a credential shown to one reader is linkable to
// the next: LinkableCredentials names it, and only it.
func TestProximityRespondDocuments_LinkableCredentials(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 1})
	w := multiWallet(t, f, f.keys, walletflow.ProximityDeviceSignature)
	ids := receiveThree(t, f, w)
	ctx := context.Background()
	first, _ := askThree(t, w)
	if _, err := first.RespondDocuments(ctx, []walletflow.MdocAnswer{answer(ids, 0)}); err != nil {
		t.Fatal(err)
	}
	// An unsigned reader is a new Verifier each session.
	second, _ := askThree(t, w)
	presented, err := second.RespondDocuments(ctx, []walletflow.MdocAnswer{answer(ids, 1), answer(ids, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if !presented.Linkable || !slices.Equal(presented.LinkableCredentials, []string{ids[0]}) {
		t.Errorf("Linkable %v, LinkableCredentials %v; want true, [%s]", presented.Linkable, presented.LinkableCredentials, ids[0])
	}
}

// askThreeDCAPI builds an org-iso-mdoc request from origin for
// family_name and given_name from each of multiDocTypes, signed by
// reader, and starts its presentation.
func askThreeDCAPI(t *testing.T, w *walletflow.Wallet, reader mdocReader) (*walletflow.MdocPresentation, mdocdcapi.Pending) {
	t.Helper()
	var docs []mdocdcapi.DocumentRequest
	for i, dt := range multiDocTypes {
		docs = append(docs, mdocdcapi.DocumentRequest{DocType: dt, Elements: map[string]map[string]bool{multiNameSpaces[i]: {"family_name": false, "given_name": false}}})
	}
	req, err := mdocdcapi.BuildRequest(mdocdcapi.RequestParams{Origin: shopOrigin, Documents: docs, Readers: []mdocdcapi.ReaderKey{reader.key}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(req.Data)
	if err != nil {
		t.Fatal(err)
	}
	p, err := w.StartMdocPresentation(context.Background(), data, shopOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Requests(); len(got) != 3 || p.Reader() == nil {
		t.Fatalf("%d requests, reader %v", len(got), p.Reader())
	}
	return p, req.Pending
}

func verifyDCAPI(t *testing.T, f fixture, pending mdocdcapi.Pending, presented walletflow.MdocPresented) []mdocdcapi.Verified {
	t.Helper()
	vs, err := mdocdcapi.VerifyResponseDocuments(context.Background(), mdocdcapi.VerifyParams{
		Pending: pending, Response: base64.RawURLEncoding.EncodeToString(presented.EncryptedResponse),
		IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: f.env.IssuerRoots, Revocation: certrevocation.NoCheck{}},
		Assurance:  verifier.AssuranceDevelopment, NoStatusCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

// Over the Digital Credentials API, the answers go in one
// EncryptedResponse, in the request's order; a cancelled prompt sends
// nothing and releases every copy, and the request can be answered
// again.
func TestMdocPresentationRespondDocuments(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 1})
	reader := newMdocReader(t)
	keys := newHolderKeys(f)
	w := multiWallet(t, f, keys, walletflow.ProximityDeviceSignature, &reader)
	ids := receiveThree(t, f, w)
	ctx := context.Background()
	p, pending := askThreeDCAPI(t, w, reader)
	answers := []walletflow.MdocAnswer{answer(ids, 2), answer(ids, 0)}

	keys.failAt = 2
	keys.armed.Store(true)
	if _, err := p.RespondDocuments(ctx, answers); !errors.Is(err, errCancelled) {
		t.Fatalf("RespondDocuments with a cancelled prompt = %v", err)
	}
	for _, id := range ids {
		stored, err := f.store.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if cp := stored.AllCopies()[0]; cp.Presented || len(cp.ShownTo) != 0 {
			t.Errorf("after a cancelled prompt %s's copy is %+v", id, cp)
		}
	}
	keys.failAt = 0
	if _, err := p.RespondDocuments(ctx, []walletflow.MdocAnswer{answer(ids, 0), answer(ids, 0)}); !errors.Is(err, walletflow.ErrInvalidSelection) {
		t.Errorf("a request answered twice: %v", err)
	}

	presented, err := p.RespondDocuments(ctx, answers)
	if err != nil {
		t.Fatal(err)
	}
	vs := verifyDCAPI(t, f, pending, presented)
	if len(vs) != 2 || vs[0].DocType != walletflowtest.DocType || vs[1].DocType != walletflowtest.DocType3 {
		t.Fatalf("verified %d documents %+v, want %s then %s", len(vs), vs, walletflowtest.DocType, walletflowtest.DocType3)
	}
	for n, i := range []int{0, 2} {
		if got := vs[n].NameSpaces[multiNameSpaces[i]]; len(vs[n].NameSpaces) != 1 || len(got) != 1 || got["family_name"] != walletflowtest.FamilyName {
			t.Errorf("%s disclosed %v, want only family_name", vs[n].DocType, vs[n].NameSpaces)
		}
	}
	if _, err := p.RespondDocuments(ctx, answers); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("a second RespondDocuments: %v", err)
	}
}
