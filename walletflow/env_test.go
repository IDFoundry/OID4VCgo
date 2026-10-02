package walletflow_test

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// testEnv is a walletflowtest.Env that fails t instead of returning
// errors.
type testEnv struct{ *walletflowtest.Env }

func newEnv(t *testing.T, opts walletflowtest.Options) testEnv {
	t.Helper()
	e, err := walletflowtest.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return testEnv{e}
}

func (e testEnv) AuthorizationCodeOffer(t *testing.T, configIDs ...string) string {
	t.Helper()
	uri, err := e.Env.AuthorizationCodeOffer(configIDs...)
	if err != nil {
		t.Fatal(err)
	}
	return uri
}

func (e testEnv) PreAuthorizedOffer(t *testing.T, pin string, configIDs ...string) string {
	t.Helper()
	uri, err := e.Env.PreAuthorizedOffer(pin, configIDs...)
	if err != nil {
		t.Fatal(err)
	}
	return uri
}

func (e testEnv) StartVerifier(t *testing.T) testVerifier {
	t.Helper()
	v, err := e.Env.StartVerifier()
	if err != nil {
		t.Fatal(err)
	}
	return testVerifier{v}
}

func (e testEnv) SDJWTQuery(t *testing.T, id string, claims ...string) dcql.CredentialQuery {
	t.Helper()
	q, err := e.Env.SDJWTQuery(id, claims...)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func mdocQuery(t *testing.T, id string, elements ...string) dcql.CredentialQuery {
	t.Helper()
	q, err := walletflowtest.MdocQuery(id, elements...)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// testVerifier is a walletflowtest.Verifier that fails t instead of
// returning errors.
type testVerifier struct{ *walletflowtest.Verifier }

func (v testVerifier) Begin(t *testing.T, query dcql.Query) (id, link string) {
	t.Helper()
	id, link, err := v.Verifier.Begin(query)
	if err != nil {
		t.Fatal(err)
	}
	return id, link
}

func (v testVerifier) Lookup(t *testing.T, id string) verifier.TransactionView {
	t.Helper()
	view, err := v.Verifier.Lookup(id)
	if err != nil {
		t.Fatal(err)
	}
	return view
}
