# Builds cmd/conformance-wallet-vp for the docker-compose setup in
# this directory. Build context is the repo root (../.. from here) —
# mirrors conformance/verifier/Dockerfile exactly.
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/conformance-wallet-vp ./cmd/conformance-wallet-vp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/conformance-wallet-vp /conformance-wallet-vp
ENTRYPOINT ["/conformance-wallet-vp"]
