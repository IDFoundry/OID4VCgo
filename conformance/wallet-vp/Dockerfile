# Builds cmd/conformance-wallet-vp for the docker-compose setup in
# this directory. Build context is the repo root (../.. from here) —
# mirrors conformance/verifier/Dockerfile exactly.
FROM golang:1.26.11@sha256:957952ae74dc010608717144399a59a2c6e82ea03d63be1c7ff6577c5a135f93 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/conformance-wallet-vp ./cmd/conformance-wallet-vp

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/conformance-wallet-vp /conformance-wallet-vp
ENTRYPOINT ["/conformance-wallet-vp"]
