module github.com/idfoundry/oid4vcgo/mobile

go 1.26.6

require (
	github.com/fxamacker/cbor/v2 v2.9.4
	github.com/idfoundry/fapigo v0.46.1-0.20261004044051-3e70d32c99f6
	github.com/idfoundry/oid4vcgo v0.0.0
)

require (
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
)

replace github.com/idfoundry/oid4vcgo => ..

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
