package verifier_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// An answer is refused where it first makes itself one the request
// can't take, not after all of it is decoded (DOS-1 of the 2026-11-18
// audit): a vp_token at its first member that isn't one of the
// query's credential queries, or at its 33rd presentation for one; a
// payload, or a Digital Credentials API post, of many small tokens at
// the bound on them.
func TestTransactions_RefusesTokenDenseAnswersEarly(t *testing.T) {
	f := newTxFixture(t, nil)
	f.query.Credentials[0].Multiple = true
	ctx := context.Background()

	// payload encrypts plaintext, its state set to the request's, as an
	// answer to a new request.
	answer := func(plaintext func(state string) string) error {
		t.Helper()
		begun := f.begin("browser-binding-A", false)
		object, err := f.txs.RequestObject(ctx, begun.ID)
		if err != nil {
			t.Fatal(err)
		}
		link, _ := url.Parse(begun.Link)
		req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
			RequestObject: object, ClientID: link.Query().Get("client_id"), VerifierTrust: wallet.NoVerifierTrust{},
		})
		if err != nil {
			t.Fatal(err)
		}
		compact, err := jwe.Encrypt(req.ResponseEncryptionKey, jwe.Enc(req.ResponseEncryptionEnc), []byte(plaintext(req.State)), jwe.EncryptOptions{KeyID: req.ResponseEncryptionKeyID})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.txs.HandleResponse(ctx, compact)
		return err
	}
	withVPToken := func(vpToken string) func(string) string {
		return func(state string) string {
			s, _ := json.Marshal(state)
			return `{"state":` + string(s) + `,"vp_token":` + vpToken + `}`
		}
	}
	reasonOf := func(err error) verifier.Reason {
		var e *verifier.Error
		if errors.As(err, &e) {
			return e.Reason()
		}
		return ""
	}

	// The rest of the vp_token is never decoded: one more member would
	// otherwise be refused for its type.
	err := answer(withVPToken(`{"cred":["x"],"other":["y"],"more":{}}`))
	if reasonOf(err) != verifier.ReasonNotAnswered || !strings.Contains(err.Error(), "the request doesn't make") {
		t.Errorf("an id the query doesn't have: %v, want it refused as not answered at the id", err)
	}
	err = answer(withVPToken(`{"cred":[` + strings.Repeat(`"x",`, verifier.MaxPresentationsPerQuery) + `{}]}`))
	if reasonOf(err) != verifier.ReasonMalformed || !strings.Contains(err.Error(), "more than 32 presentations") {
		t.Errorf("33 presentations: %v, want them refused at the 33rd", err)
	}
	err = answer(withVPToken(`{"cred":["x"]},"pad":[` + strings.Repeat("0,", strictjson.DefaultMaxTokens) + `0]`))
	if !errors.Is(err, strictjson.ErrTooManyTokens) {
		t.Errorf("a payload of many small tokens: %v, want ErrTooManyTokens", err)
	}

	begun := f.beginDCAPI(testBinding)
	// Far fewer tokens than strictjson.DefaultMaxTokens, and far fewer
	// bytes than MaxDCAPIResponseBytes.
	data := []byte(`{"x":[` + strings.Repeat("0,", 4096) + `0]}`)
	if _, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, data); !errors.Is(err, strictjson.ErrTooManyTokens) {
		t.Errorf("a Digital Credentials API post of many small tokens: %v, want ErrTooManyTokens", err)
	}
	// An error with its description is within the bound.
	data = []byte(`{"error":"access_denied","error_description":"the holder declined"}`)
	var walletErr *verifier.ResponseError
	if _, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, data); !errors.As(err, &walletErr) {
		t.Errorf("a Digital Credentials API error: %v, want a *ResponseError", err)
	}
}
