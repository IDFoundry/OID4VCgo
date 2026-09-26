package oid4vci

import (
	"encoding/json"
	"strings"
	"testing"
)

const minimalMetadataJSON = `"credential_issuer":"https://issuer.example.com","credential_endpoint":"https://issuer.example.com/credential","credential_configurations_supported":{}`

func TestMetadata_AuthorizationServers(t *testing.T) {
	var m Metadata
	raw := `{` + minimalMetadataJSON + `,"authorization_servers":["https://as1.example.com","https://as2.example.com/tenant"]}`
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(m.AuthorizationServers) != 2 || m.AuthorizationServers[0].String() != "https://as1.example.com" ||
		m.AuthorizationServers[1].String() != "https://as2.example.com/tenant" {
		t.Fatalf("AuthorizationServers = %v", m.AuthorizationServers)
	}

	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back Metadata
	if err := json.Unmarshal(out, &back); err != nil || len(back.AuthorizationServers) != 2 {
		t.Fatalf("round trip: %v, %v", back.AuthorizationServers, err)
	}
}

func TestMetadata_AuthorizationServersOmittedWhenAbsent(t *testing.T) {
	var m Metadata
	if err := json.Unmarshal([]byte(`{`+minimalMetadataJSON+`}`), &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if m.AuthorizationServers != nil {
		t.Errorf("AuthorizationServers = %v, want nil", m.AuthorizationServers)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(out), "authorization_servers") {
		t.Errorf("marshaled %s, want authorization_servers omitted", out)
	}
}

func TestMetadata_AuthorizationServersRejectsInsecureURL(t *testing.T) {
	var m Metadata
	raw := `{` + minimalMetadataJSON + `,"authorization_servers":["http://as.example.com"]}`
	err := json.Unmarshal([]byte(raw), &m)
	if err == nil || !strings.Contains(err.Error(), "authorization_servers[0]") {
		t.Errorf("Unmarshal error = %v, want an authorization_servers[0] rejection", err)
	}
}
