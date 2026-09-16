# Builds cmd/conformance-issuer for the docker-compose setup in this
# directory. Build context is the repo root (../.. from here) —
# mirrors conformance/verifier/Dockerfile and
# conformance/wallet-vp/Dockerfile exactly.
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/conformance-issuer ./cmd/conformance-issuer

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/conformance-issuer /conformance-issuer
ENTRYPOINT ["/conformance-issuer"]
