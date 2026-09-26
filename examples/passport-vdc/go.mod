module github.com/idfoundry/oid4vcgo/examples/passport-vdc

go 1.26.6

require (
	github.com/fxamacker/cbor/v2 v2.9.4
	github.com/gmrtd/gmrtd v1.2.0
	github.com/idfoundry/fapigo v0.33.0
	github.com/idfoundry/oid4vcgo v0.0.0-00010101000000-000000000000
)

require (
	github.com/aead/cmac v0.0.0-20160719120800-7af84192f0b1 // indirect
	github.com/osanderson/brainpool v1.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)

// The demo always builds against this checkout of the library, not a
// published release, so a library change and the demo using it land
// together.
replace github.com/idfoundry/oid4vcgo => ../..
