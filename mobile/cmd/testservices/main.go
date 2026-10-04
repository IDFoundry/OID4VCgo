// Command testservices runs walletflowtest's HAIP issuer and Verifier,
// and a Wallet Provider with the passport-vdc demo's HTTP API, for
// driving the iOS demo wallet app end to end on the Simulator (see
// mobile/ios/DemoWallet). A control endpoint on -addr serves the app's
// configuration and fresh Credential Offers:
//
//	GET  /config                 → {"wallet": NewWallet config, "provider_url"}
//	POST /offer?pin=<digits>     → {"offer"}  (no pin: the authorization code grant)
//	POST /request?format=<fmt>   → {"id", "link"}: the Verifier asks for family_name
//	                               from an SD-JWT VC ("dc+sd-jwt"), an mdoc
//	                               ("mso_mdoc") or either (no format); with
//	                               multiple=1, from one or more credentials
//	                               (DCQL multiple); with registered=1, from a
//	                               Verifier registered for family_name only, also
//	                               asking for extra=<claim> if given
//	GET  /request/{id}           → {"status": "pending" | "done", "claims", "credentials",
//	                               "last_error"}: claims are the first credential's,
//	                               credentials how many were presented
//	POST /defer?on=1             → the issuer defers every credential from now on
//	                               (on=0: issues at once), each awaiting /decide
//	POST /decide?approve=1       → approves (approve=0: denies) every deferred
//	                               credential, on its next poll
//	POST /revoke                 → revokes every credential issued so far
//	POST /revoke-grants          → revokes every authorization code grant so far:
//	                               refreshing a credential is then reissue_required
//
// Every service is HTTPS with one self-signed certificate, written to
// -cert for the Simulator to trust (xcrun simctl keychain booted
// add-root-cert). It is test infrastructure: it attests anything, and its
// issuer approves every request at once.
package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/mobile/internal/devjwk"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8600", "control endpoint address")
	redirect := flag.String("redirect", "dev.idfoundry.oid4vcgo.demowallet:/callback", "the app's redirect URI, registered with the issuer")
	certOut := flag.String("cert", "", "write the services' TLS certificate here, as PEM")
	flag.Parse()
	if err := run(*addr, *redirect, *certOut); err != nil {
		log.Fatal(err)
	}
}

func run(addr, redirect, certOut string) error {
	// Batches of three: the app presents a fresh copy each time.
	env, err := walletflowtest.New(walletflowtest.Options{RedirectURIs: []string{redirect}, BatchSize: 3})
	if err != nil {
		return err
	}
	defer env.Close()
	v, err := env.StartVerifier()
	if err != nil {
		return err
	}
	// A Verifier the registrar registered for family_name only.
	rv, err := env.StartRegisteredVerifier(dcql.Path{dcql.PathKey("family_name")}, dcql.Path{dcql.PathKey(walletflowtest.NameSpace), dcql.PathKey("family_name")})
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: env.TLSCertificate.Raw})
	if certOut != "" {
		if err := os.WriteFile(certOut, certPEM, 0o600); err != nil {
			return err
		}
	}

	provider := httptest.NewTLSServer(providerHandler(env.Provider))
	defer provider.Close()

	config := map[string]any{
		"wallet": map[string]any{
			"client_id": walletflowtest.ClientID, "redirect_uri": redirect, "development": true, "request_refresh": true,
			"issuer_roots": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: env.IssuerCA.Raw})),
			"verifier_roots": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.CA.Raw})) +
				string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rv.CA.Raw})),
			"registrar_roots": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: env.RegistrarCA.Raw})),
		},
		"provider_url": provider.URL,
	}
	mux := services{env: env, v: v, rv: rv}.routes(config)
	control := httptest.NewUnstartedServer(mux)
	if err := control.Listener.Close(); err != nil {
		return err
	}
	if control.Listener, err = netListen(addr); err != nil {
		return err
	}
	control.StartTLS()
	defer control.Close()

	fmt.Printf("test services: control %s, issuer %s, provider %s\n", control.URL, env.IssuerURL, provider.URL)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return nil
}

// services are the control endpoints, over the test issuer, its
// Verifier v and the registered Verifier rv.
type services struct {
	env   *walletflowtest.Env
	v, rv *walletflowtest.Verifier
}

func (s services) routes(config map[string]any) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /config", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, config) })
	mux.HandleFunc("POST /offer", s.handleOffer)
	mux.HandleFunc("POST /request", s.handleRequest)
	mux.HandleFunc("GET /request/{id}", s.handleResult)
	mux.HandleFunc("POST /defer", func(w http.ResponseWriter, r *http.Request) {
		s.env.SetDefer(r.URL.Query().Get("on") == "1")
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /decide", func(w http.ResponseWriter, r *http.Request) {
		s.env.Decide(r.URL.Query().Get("approve") == "1")
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, _ *http.Request) {
		s.env.Revoke()
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /revoke-grants", func(w http.ResponseWriter, _ *http.Request) {
		s.env.RevokeGrants()
		writeJSON(w, map[string]bool{"ok": true})
	})
	return mux
}

func (s services) handleOffer(w http.ResponseWriter, r *http.Request) {
	var offer string
	var err error
	if pin := r.URL.Query().Get("pin"); pin != "" {
		offer, err = s.env.PreAuthorizedOffer(pin, walletflowtest.SDJWTConfigurationID)
	} else {
		offer, err = s.env.AuthorizationCodeOffer(walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"offer": offer})
}

func (s services) handleRequest(w http.ResponseWriter, r *http.Request) {
	q, err := query(s.env, r.URL.Query().Get("format"), r.URL.Query().Get("multiple") == "1")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	asker := s.v
	if r.URL.Query().Get("registered") == "1" {
		asker = s.rv
		askAlso(&q, r.URL.Query().Get("extra"))
	}
	id, link, err := asker.Begin(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"id": id, "link": link})
}

// askAlso adds claim, if set, to each of q's credential queries.
func askAlso(q *dcql.Query, claim string) {
	if claim == "" {
		return
	}
	for i := range q.Credentials {
		path := dcql.Path{dcql.PathKey(claim)}
		if q.Credentials[i].Format == "mso_mdoc" {
			path = dcql.Path{dcql.PathKey(walletflowtest.NameSpace), dcql.PathKey(claim)}
		}
		q.Credentials[i].Claims = append(q.Credentials[i].Claims, dcql.ClaimsQuery{Path: path})
	}
}

func (s services) handleResult(w http.ResponseWriter, r *http.Request) {
	view, err := s.v.Lookup(r.PathValue("id"))
	if err != nil {
		view, err = s.rv.Lookup(r.PathValue("id"))
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	out := map[string]any{"status": "pending", "last_error": view.LastError}
	if view.Result != nil && len(view.Result.Credentials) > 0 {
		out["status"], out["claims"] = "done", view.Result.Credentials[0].Claims
		out["credentials"] = len(view.Result.Credentials)
	}
	writeJSON(w, out)
}

// providerHandler serves walletflowtest's Wallet Provider with the
// passport-vdc demo Wallet Provider's API (examples/passport-vdc/
// walletprovider): POST a JSON request, get {"attestation"}.
func providerHandler(p *walletflowtest.Provider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /wallet-attestation", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ClientID    string          `json:"client_id"`
			InstanceKey json.RawMessage `json:"instance_key"`
		}
		if !decode(w, r, &req) {
			return
		}
		key, err := devjwk.ParseP256(req.InstanceKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jwt, err := p.WalletAttestation(r.Context(), req.ClientID, key)
		writeAttestation(w, jwt, err)
	})
	mux.HandleFunc("POST /key-attestation", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Keys  json.RawMessage `json:"keys"`
			Nonce string          `json:"nonce"`
		}
		if !decode(w, r, &req) {
			return
		}
		keys, err := devjwk.ParseP256Set(req.Keys)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jwt, err := p.KeyAttestation(r.Context(), keys, req.Nonce)
		writeAttestation(w, jwt, err)
	})
	return mux
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return false
	}
	return true
}

func writeAttestation(w http.ResponseWriter, jwt string, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"attestation": jwt})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func netListen(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }

// query asks for family_name from an SD-JWT VC, an mdoc, or either;
// from one or more credentials when multiple is set.
func query(env *walletflowtest.Env, format string, multiple bool) (dcql.Query, error) {
	sdjwt, err := env.SDJWTQuery("pid", "family_name")
	if err != nil {
		return dcql.Query{}, err
	}
	mdoc, err := walletflowtest.MdocQuery("mdl", "family_name")
	if err != nil {
		return dcql.Query{}, err
	}
	sdjwt.Multiple, mdoc.Multiple = multiple, multiple
	switch format {
	case "dc+sd-jwt":
		return dcql.Query{Credentials: []dcql.CredentialQuery{sdjwt}}, nil
	case "mso_mdoc":
		return dcql.Query{Credentials: []dcql.CredentialQuery{mdoc}}, nil
	default:
		return dcql.Query{
			Credentials:    []dcql.CredentialQuery{mdoc, sdjwt},
			CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{"mdl"}, {"pid"}}}},
		}, nil
	}
}
