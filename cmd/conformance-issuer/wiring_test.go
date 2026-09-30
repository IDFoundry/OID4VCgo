package main

import (
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

func TestLocalResourceAccessTokens_RequiresIssuer(t *testing.T) {
	if _, err := localResourceAccessTokens(fapi.URL{}, nil, time.Minute); err == nil {
		t.Fatal("localResourceAccessTokens with no issuer: want error")
	}
}
