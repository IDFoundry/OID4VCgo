package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/url"
	"path/filepath"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// Each issuance config document's $schema, as EUDIPLO 10.1 publishes them.
const (
	issuanceSchema   = schemaBase + "v7/IssuanceConfigFile.schema.json"
	credentialSchema = schemaBase + "v5/CredentialConfigFile.schema.json"
	statusListSchema = schemaBase + "v1/StatusListConfigFile.schema.json"
)

// encTenant is the second tenant's id: the same issuer as tenant's, but
// requiring Credential Request and Response encryption, which EUDIPLO
// sets per tenant.
const encTenant = tenant + "-enc"

// Key chain and trust list ids of the issuer's.
const (
	sdjwtKeyChain      = "oid4vcgo-sdjwt-signer"
	mdocKeyChain       = "oid4vcgo-mdoc-signer"
	statusKeyChain     = "oid4vcgo-status-list"
	mdocStatusKeyChain = "oid4vcgo-mdoc-status-list"
	walletProviderList = "wallet-providers"
)

// The PID's claims EUDIPLO issues, the same in every configuration.
var pidClaims = map[string]string{"family_name": "MUSTERMANN", "given_name": "ERIKA", "birth_date": "1964-08-12"}

// issuerKeys are the keys and certificates EUDIPLO's issuer signs
// with: SD-JWT VCs and their status lists under one CA, mdocs and
// theirs under an IACA.
type issuerKeys struct {
	sdjwt, status, ds, mdocStatus       *ecdsa.PrivateKey
	sdjwtCert, statusCert, dsC, mdocStC string
}

// newIssuerKeys makes the issuer's keys, and adds their CAs to f as
// eudiplo-issuer-ca.pem and eudiplo-iaca.pem. The SD-JWT VCs' status
// list signer's certificate names statusIssuer, the iss EUDIPLO gives
// its status lists (its PUBLIC_URL, not a tenant's credential issuer):
// a Status Issuer, which a wallet accepts for the tenants' credentials
// when it's told so (walletflow.Config.StatusIssuers).
func newIssuerKeys(f files, statusIssuer string) (issuerKeys, error) {
	var k issuerKeys
	ca, caKey, caPEM, _, err := conformancecert.GenerateCA("OID4VCgo EUDIPLO interop issuer CA")
	if err != nil {
		return k, err
	}
	leaf := func(name string, uris ...*url.URL) (*ecdsa.PrivateKey, string, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", err
		}
		cert, err := conformancecert.IssueLeafCertPEM(name, key, ca, caKey, uris...)
		return key, cert, err
	}
	if k.sdjwt, k.sdjwtCert, err = leaf("OID4VCgo EUDIPLO interop SD-JWT VC signer"); err != nil {
		return k, err
	}
	name, err := url.Parse(statusIssuer)
	if err != nil {
		return k, err
	}
	if k.status, k.statusCert, err = leaf("OID4VCgo EUDIPLO interop status list signer", name); err != nil {
		return k, err
	}
	iaca, iacaKey, iacaPEM, _, err := conformancecert.GenerateMdocIACA("OID4VCgo EUDIPLO interop IACA", "AT", "mailto:interop@example.com")
	if err != nil {
		return k, err
	}
	if k.ds, _, k.dsC, err = conformancecert.GenerateMdocDocumentSigner("OID4VCgo EUDIPLO interop DS", "AT",
		"mailto:interop@example.com", "https://crl.eudiplo.test/iaca.crl", iaca, iacaKey); err != nil {
		return k, err
	}
	// The mdocs' status list signer, under the IACA that signed their
	// Document Signer (ISO/IEC 18013-5 §12.3.6.2).
	if k.mdocStatus, _, k.mdocStC, err = conformancecert.GenerateMdocRevocationListSigner("OID4VCgo EUDIPLO interop mdoc status list signer",
		"AT", iaca, iacaKey); err != nil {
		return k, err
	}
	f["eudiplo-issuer-ca.pem"], f["eudiplo-iaca.pem"] = caPEM, iacaPEM
	return k, nil
}

// issuerFiles adds to f the issuer of tenant name: its key chains, the
// trust list naming OID4VCgo's Wallet Provider's CA (wpCA) as a wallet
// provider, the issuance config (the built-in authorization server,
// Wallet Attestations and DPoP required, attestations' status checked
// strictly, batches of 2; with encrypted, Credential Request and
// Response encryption required) and the credential configs pid-sdjwt,
// pid-mdoc, pid-sdjwt-ka (a Key Attestation required, key storage
// iso_18045_moderate, which the provider attests, in a jwt proof's
// key_attestation), pid-sdjwt-kap (the same, as an attestation proof)
// and pid-sdjwt-ka-high (iso_18045_high, which the provider doesn't
// attest).
func issuerFiles(f files, name string, k issuerKeys, listKey *ecdsa.PrivateKey, wpCA string, encrypted bool) error {
	at := func(parts ...string) string {
		return filepath.Join(append([]string{"eudiplo", "config", name}, parts...)...)
	}
	docs := map[string]any{
		at("key-chains", "sdjwt-signer.json"): signer(sdjwtKeyChain, "attestation", "signs SD-JWT VCs", k.sdjwt, k.sdjwtCert),
		at("key-chains", "mdoc-signer.json"):  signer(mdocKeyChain, "attestation", "signs mdocs (Document Signer)", k.ds, k.dsC),
		at("key-chains", "status-list.json"):  signer(statusKeyChain, "statusList", "signs SD-JWT VCs' status lists", k.status, k.statusCert),
		at("key-chains", "mdoc-status-list.json"): signer(mdocStatusKeyChain, "statusList", "signs mdocs' status lists",
			k.mdocStatus, k.mdocStC),
		at("issuance", "status-lists", "pid-sdjwt.json"): statusList("pid-sdjwt", statusKeyChain),
		at("issuance", "status-lists", "pid-mdoc.json"):  statusList("pid-mdoc", mdocStatusKeyChain),
		at("trust-lists", walletProviderList+".json"): trustList(walletProviderList, "OID4VCgo's Wallet Provider",
			walletProvider("OID4VCgo interop Wallet Provider", wpCA)),
		at("issuance", "issuance.json"): doc(issuanceSchema, map[string]any{
			"authorizationServers": []map[string]any{{
				"type": "built-in", "id": "issuer-built-in", "requireDPoP": true, "walletAttestationRequired": true,
			}},
			"batchSize": 2, "dPopRequired": true,
			"walletAttestationRequired": true, "walletAttestationStatusCheckMode": "strict",
			"walletProviderTrustLists":    []map[string]string{{"trustListId": walletProviderList}},
			"credentialRequestEncryption": encrypted, "credentialResponseEncryption": encrypted,
			"display": []map[string]string{{"locale": "en-US", "name": "OID4VCgo interop (EUDIPLO)"}},
		}),
		at("issuance", "credentials", "pid-sdjwt.json"):         sdjwtCredential("pid-sdjwt", nil, nil),
		at("issuance", "credentials", "pid-mdoc.json"):          mdocCredential("pid-mdoc"),
		at("issuance", "credentials", "pid-sdjwt-ka.json"):      sdjwtCredential("pid-sdjwt-ka", moderate, []string{"jwt"}),
		at("issuance", "credentials", "pid-sdjwt-kap.json"):     sdjwtCredential("pid-sdjwt-kap", moderate, []string{"attestation"}),
		at("issuance", "credentials", "pid-sdjwt-ka-high.json"): sdjwtCredential("pid-sdjwt-ka-high", []string{"iso_18045_high"}, []string{"jwt"}),
	}
	if name != tenant {
		// The Verifier's tenant has its trust list key chain already.
		docs[at("key-chains", "trust-list.json")] = trustListKeyChainDoc(listKey)
	}
	for path, v := range docs {
		if err := f.json(path, v); err != nil {
			return err
		}
	}
	return nil
}

// statusList is the status list of credential config id, signed by key
// chain keyChain; the other configs share one.
func statusList(id, keyChain string) map[string]any {
	return doc(statusListSchema, map[string]any{
		"id": id + "-status", "credentialConfigurationId": id, "keyChainId": keyChain, "capacity": 10000, "bits": 1,
	})
}

// signer is a standalone key chain of usage for k, its certificate cert.
func signer(id, usage, description string, k *ecdsa.PrivateKey, cert string) map[string]any {
	return doc(keyChainSchema, map[string]any{
		"id": id, "description": description, "usageType": usage, "type": "standalone",
		"keySource":   map[string]any{"type": "private-jwk", "jwk": privateJWK(k, id)},
		"kmsProvider": "db", "crt": []string{cert},
	})
}

// trustListKeyChainDoc is the key chain that signs a tenant's trust lists.
func trustListKeyChainDoc(k *ecdsa.PrivateKey) map[string]any {
	return doc(keyChainSchema, map[string]any{
		"id": trustListKeyChain, "description": "signs the tenant's trust lists", "usageType": "trustList",
		"keySource":   map[string]any{"type": "private-jwk", "jwk": privateJWK(k, trustListKeyChain)},
		"kmsProvider": "db",
	})
}

// walletProvider is entity's wallet provider: its attestations and
// their status lists both signed under the CA certificate caPEM.
func walletProvider(name, caPEM string) map[string]any {
	e := entity(name, caPEM)
	e["providerType"] = "wallet-provider"
	return e
}

// moderate is the key storage level OID4VCgo's Wallet Provider attests
// (interop/walletprovider's policy).
var moderate = []string{"iso_18045_moderate"}

// sdjwtCredential is an SD-JWT VC PID config, bound to a key, with a
// status list entry; with keyStorage, a Key Attestation stating one of
// those levels is required, in one of proofTypes.
func sdjwtCredential(id string, keyStorage, proofTypes []string) map[string]any {
	config := map[string]any{"format": "dc+sd-jwt", "scope": id, "display": display(id)}
	if keyStorage != nil {
		config["keyAttestationsRequired"] = map[string]any{"key_storage": keyStorage}
		config["proofTypesSupported"] = proofTypes
	}
	fields := make([]map[string]any, 0, len(pidClaims))
	for _, claim := range sortedClaims() {
		fields = append(fields, map[string]any{
			"path": []string{claim}, "type": "string", "defaultValue": pidClaims[claim], "mandatory": true, "disclosable": true,
		})
	}
	return credential(id, map[string]any{"vct": pidVCT, "keyChainId": sdjwtKeyChain}, config, fields)
}

// mdocCredential is an mdoc PID config, of pidDocType.
func mdocCredential(id string) map[string]any {
	fields := make([]map[string]any, 0, len(pidClaims))
	for _, claim := range sortedClaims() {
		field := map[string]any{
			"namespace": pidNamespace, "path": []string{claim}, "type": "string", "defaultValue": pidClaims[claim], "mandatory": true,
		}
		if claim == "birth_date" {
			field["format"] = "date"
		}
		fields = append(fields, field)
	}
	config := map[string]any{"format": "mso_mdoc", "docType": pidDocType, "scope": id, "display": display(id)}
	return credential(id, map[string]any{"keyChainId": mdocKeyChain}, config, fields)
}

func credential(id string, spec, config map[string]any, fields []map[string]any) map[string]any {
	spec["id"], spec["description"], spec["config"], spec["fields"] = id, "interop/eudiplo/run.sh: "+id, config, fields
	spec["keyBinding"], spec["statusManagement"], spec["lifeTime"] = true, true, 86400
	return doc(credentialSchema, spec)
}

func display(id string) []map[string]string {
	return []map[string]string{{"locale": "en-US", "name": fmt.Sprintf("PID (%s)", id)}}
}

func sortedClaims() []string {
	return []string{"birth_date", "family_name", "given_name"}
}
