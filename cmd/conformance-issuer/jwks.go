package main

import (
	"encoding/json"
	"net/http"

	"github.com/idfoundry/fapigo/server"
)

func jwksHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		set, err := srv.PublicJWKS(r.Context())
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}
}
