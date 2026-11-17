package walletapp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// received issues both formats from a fresh demo issuer and returns
// them by format, with the issuer's CA as a pool.
func received(t *testing.T) (map[string]walletapp.Received, *x509.CertPool, *demotest.Env) {
	t.Helper()
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	got, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	byFormat := map[string]walletapp.Received{}
	for _, r := range got {
		byFormat[r.Format] = r
	}
	roots := x509.NewCertPool()
	roots.AddCert(env.Issuer.IssuerCACertificate())
	return byFormat, roots, env
}

// TestValidateReceived_Rejects covers what the wallet refuses to keep
// (wallet.VerifyIssuedCredential, which walletflow runs on every
// credential it receives):
// a credential from an issuer it doesn't trust, one bound to a key it
// didn't prove possession of, one of another type, and a tampered one.
func TestValidateReceived_Rejects(t *testing.T) {
	byFormat, roots, env := received(t)
	confs := map[string]oid4vci.CredentialConfigurationMetadata{
		"mso_mdoc":  {Format: "mso_mdoc", DocType: credential.DocType},
		"dc+sd-jwt": {Format: "dc+sd-jwt", VCT: env.IssuerURL + issuerapp.VCTPath},
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	for format, r := range byFormat {
		conf := confs[format]
		validate := func(conf oid4vci.CredentialConfigurationMetadata, cred string, holder *ecdsa.PrivateKey, roots *x509.CertPool) error {
			_, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
				Configuration: conf, Credential: cred, HolderKey: &holder.PublicKey, IssuerRoots: roots, Now: now,
			})
			return err
		}
		t.Run(format, func(t *testing.T) {
			if err := validate(conf, r.Credential, r.HolderKey, roots); err != nil {
				t.Fatalf("the issued credential doesn't validate: %v", err)
			}
			wrongType := conf
			wrongType.VCT, wrongType.DocType = "https://other.example/vct", "org.example.other.1"
			tampered := []byte(r.Credential)
			if i := len(tampered) / 2; tampered[i] == 'A' {
				tampered[i] = 'B'
			} else {
				tampered[i] = 'A'
			}
			for name, err := range map[string]error{
				"untrusted issuer": validate(conf, r.Credential, r.HolderKey, x509.NewCertPool()),
				"other holder key": validate(conf, r.Credential, otherKey, roots),
				"other type":       validate(wrongType, r.Credential, r.HolderKey, roots),
				"tampered":         validate(conf, string(tampered), r.HolderKey, roots),
			} {
				if err == nil {
					t.Errorf("%s: accepted", name)
				}
			}
		})
	}
}

// TestReceive_RefusesCredentialsFromAnUntrustedIssuer checks Receive
// itself stores nothing when the issuer's CA isn't trusted.
func TestReceive_RefusesCredentialsFromAnUntrustedIssuer(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	cfg := env.WalletConfig()
	cfg.IssuerRoots = x509.NewCertPool()
	got, err := walletapp.Receive(ctx, cfg, offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err == nil || !strings.Contains(err.Error(), "is invalid") || len(got) != 0 {
		t.Fatalf("Receive = %d credentials, %v; want none and an invalid-credential error", len(got), err)
	}
}

// countingApprover counts the authorizations it's asked for.
type countingApprover struct {
	walletapp.Approver
	calls int
}

func (a *countingApprover) Approve(ctx context.Context, authorizeURL string) (walletapp.Callback, error) {
	a.calls++
	return a.Approver.Approve(ctx, authorizeURL)
}

// TestReceive_RefusesAnUnlistedIssuer checks the wallet takes offers
// only from the issuers in Config.CredentialIssuers: an offer from
// another, its credentials signed under a trusted root, is refused
// before the holder is asked to authorize anything.
func TestReceive_RefusesAnUnlistedIssuer(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	cfg := env.WalletConfig()
	cfg.CredentialIssuers = []string{"https://other-issuer.example"}
	approver := &countingApprover{Approver: walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}}
	got, err := walletapp.Receive(ctx, cfg, offer.URI, approver)
	if !errors.Is(err, walletflow.ErrUntrustedIssuer) || len(got) != 0 || approver.calls != 0 {
		t.Fatalf("Receive = %d credentials, %v, %d authorizations; want none and ErrUntrustedIssuer", len(got), err, approver.calls)
	}
}
