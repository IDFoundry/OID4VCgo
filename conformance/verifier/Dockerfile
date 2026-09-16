# Builds cmd/conformance-verifier for the docker-compose setup in this
# directory. Build context is the repo root (../.. from here) since the
# binary needs the whole module — mirrors FAPIgo's own
# conformance/server/Dockerfile.
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/conformance-verifier ./cmd/conformance-verifier

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/conformance-verifier /conformance-verifier
ENTRYPOINT ["/conformance-verifier"]
