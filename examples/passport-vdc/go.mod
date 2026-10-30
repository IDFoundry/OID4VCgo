module github.com/idfoundry/oid4vcgo/examples/passport-vdc

go 1.26.10

require (
	github.com/fxamacker/cbor/v2 v2.9.6
	github.com/gmrtd/gmrtd v1.6.0
	github.com/idfoundry/fapigo v0.67.0
	github.com/idfoundry/fapigo/sqlstore v0.2.0
	github.com/idfoundry/oid4vcgo v0.0.0
	github.com/idfoundry/oid4vcgo/sqlstore v0.0.0-00010101000000-000000000000
	github.com/mrjoshuak/go-jpeg2000 v1.5.12
	modernc.org/sqlite v1.61.0
	rsc.io/qr v0.2.0
)

require (
	github.com/aead/cmac v0.0.0-20160719120800-7af84192f0b1 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/osanderson/brainpool v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.49.0 // indirect
	modernc.org/libc v1.79.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

// The demo always builds against this checkout of the library and its
// sqlstore module, not a published release, so a library change and the
// demo using it land together.
replace (
	github.com/idfoundry/oid4vcgo => ../..
	github.com/idfoundry/oid4vcgo/sqlstore => ../../sqlstore
)
