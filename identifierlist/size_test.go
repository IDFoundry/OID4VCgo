package identifierlist

import (
	"bytes"
	"context"
	"crypto/x509"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// TestMaxTokenBytes: a list over DefaultMaxTokenBytes is issued, served,
// verified and fetched only where its size limit is raised, and a limit
// past MaxTokenBytesLimit is an error.
func TestMaxTokenBytes(t *testing.T) {
	pki := newPKI(t)
	ctx := context.Background()
	ids := make([][]byte, DefaultMaxTokenBytes/1000+100)
	for i := range ids {
		ids[i] = append(bytes.Repeat([]byte{0}, 997), byte(i>>16), byte(i>>8), byte(i))
	}
	claims := claimsAt(time.Now(), ids...)
	const raised = 8 << 20

	_, err := IssueToken(pki.key, cose.ES256, claims, []*x509.Certificate{pki.leaf}, IssueOptions{})
	wantErr(t, "issued at the default", err, "over the")
	token := issue(t, pki, claims, IssueOptions{MaxTokenBytes: raised})
	if len(token) <= DefaultMaxTokenBytes {
		t.Fatalf("the token is %d bytes, not over DefaultMaxTokenBytes", len(token))
	}
	ref := Ref{ID: ids[0], URI: testURI}
	_, _, err = Check(ctx, token, pki.roots, ref, pki.dsPath, VerifyOptions{})
	wantErr(t, "checked at the default", err, "exceeds")
	if revoked, _, err := Check(ctx, token, pki.roots, ref, pki.dsPath, VerifyOptions{MaxTokenBytes: raised}); err != nil || !revoked {
		t.Errorf("checked with the limit raised: revoked %t, %v", revoked, err)
	}
	for name, limit := range map[string]int{"negative": -1, "over the limit": MaxTokenBytesLimit + 1} {
		_, _, err = Check(ctx, token, pki.roots, ref, pki.dsPath, VerifyOptions{MaxTokenBytes: limit})
		wantErr(t, "VerifyOptions "+name, err, "not between 0 and")
		_, err = IssueToken(pki.key, cose.ES256, claimsAt(time.Now()), []*x509.Certificate{pki.leaf}, IssueOptions{MaxTokenBytes: limit})
		wantErr(t, "IssueOptions "+name, err, "not between 0 and")
	}

	pub := &Publisher{
		Signer: pki.key, Chain: []*x509.Certificate{pki.leaf}, MaxTokenBytes: raised,
		Identifiers: func(context.Context) ([][]byte, error) { return ids, nil },
	}
	srv := httptest.NewTLSServer(pub)
	defer srv.Close()
	pub.URI = srv.URL
	ref = Ref{ID: ids[0], URI: srv.URL}
	fetcher := statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}
	for name, tc := range map[string]struct {
		c    Checker
		want string
	}{
		"default":                     {Checker{Fetcher: fetcher, Roots: pki.roots}, "exceeds"},
		"Fetcher.MaxBytes raised":     {Checker{Fetcher: withMaxBytes(fetcher, raised), Roots: pki.roots}, ""},
		"Options.MaxTokenBytes":       {Checker{Fetcher: fetcher, Roots: pki.roots, Options: VerifyOptions{MaxTokenBytes: raised}}, ""},
		"Fetcher raised, Options not": {Checker{Fetcher: withMaxBytes(fetcher, raised), Roots: pki.roots, Options: VerifyOptions{MaxTokenBytes: DefaultMaxTokenBytes}}, "exceeds"},
		"cached":                      {Checker{Fetcher: withMaxBytes(fetcher, raised), Roots: pki.roots, Cache: statuslist.NewCache(statuslist.CacheOptions{})}, ""},
	} {
		revoked, _, err := tc.c.Check(ctx, ref, pki.dsPath)
		if tc.want != "" {
			wantErr(t, name, err, tc.want)
			continue
		}
		if err != nil || !revoked {
			t.Errorf("%s: revoked %t, %v", name, revoked, err)
		}
	}
}

func withMaxBytes(f statuslist.Fetcher, n int) statuslist.Fetcher {
	f.MaxBytes = n
	return f
}
