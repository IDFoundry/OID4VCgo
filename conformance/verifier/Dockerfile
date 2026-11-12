# Builds cmd/conformance-verifier for the docker-compose setup in this
# directory. Build context is the repo root (../.. from here) since the
# binary needs the whole module — mirrors FAPIgo's own
# conformance/server/Dockerfile.
#
# GO_BUILD_TAGS=conformance_production builds the transactions engine's
# production store (cmd/conformance-verifier/production.go), which is
# sqlstore's: that build needs a Go workspace holding ./sqlstore as
# well, as conformance/issuer/Dockerfile's does.
FROM golang:1.26.11@sha256:7af425da11f4fc1a9308eb704369e3f6d1c44e35bac0f874a59ade3f20fdc07e AS build
ARG GO_BUILD_TAGS=""
WORKDIR /src
COPY . .
RUN if [ -n "$GO_BUILD_TAGS" ]; then go work init . ./sqlstore; fi && \
    CGO_ENABLED=0 go build -tags "$GO_BUILD_TAGS" -o /out/conformance-verifier ./cmd/conformance-verifier

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/conformance-verifier /conformance-verifier
ENTRYPOINT ["/conformance-verifier"]
