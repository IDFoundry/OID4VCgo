# Builds cmd/conformance-issuer for the docker-compose setup in this
# directory. Build context is the repo root (../.. from here) —
# mirrors conformance/verifier/Dockerfile and
# conformance/wallet-vp/Dockerfile exactly.
#
# GO_BUILD_TAGS=conformance_production builds the production setup
# (cmd/conformance-issuer/production.go), whose stores are sqlstore's:
# that build needs a Go workspace holding ./sqlstore as well.
FROM golang:1.26.11@sha256:4165ee6bf3b7811fd7b40373290405c83d0167dcb87ee5f29c427cdcef45ff8f AS build
ARG GO_BUILD_TAGS=""
WORKDIR /src
COPY . .
RUN if [ -n "$GO_BUILD_TAGS" ]; then go work init . ./sqlstore; fi && \
    CGO_ENABLED=0 go build -tags "$GO_BUILD_TAGS" -o /out/conformance-issuer ./cmd/conformance-issuer

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/conformance-issuer /conformance-issuer
ENTRYPOINT ["/conformance-issuer"]
