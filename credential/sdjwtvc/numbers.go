package sdjwtvc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
)

// MaxSafeInteger is the largest magnitude an SD-JWT VC's numbers may
// have: 2^53 − 1, the largest integer a float64 holds exactly with
// every integer below it (I-JSON, RFC 7493 §2.2). A claim decodes into
// a float64, and above it two integers can share one: 2^53 + 1 decodes
// as 2^53, so two values an issuer signed apart would verify as one.
// Carry an identifier, or any number beyond it, as a string.
const MaxSafeInteger = 1<<53 - 1

// checkNumbers refuses data, a JSON document, holding a number beyond
// ±MaxSafeInteger, whatever its form: an integer, a fraction or an
// exponent.
func checkNumbers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return err
		}
		n, ok := tok.(json.Number)
		if !ok {
			continue
		}
		if f, err := strconv.ParseFloat(n.String(), 64); err != nil || math.Abs(f) > MaxSafeInteger {
			return fmt.Errorf("the number %.40s is beyond ±(2^53 − 1), which a JSON number decodes to exactly: carry it as a string", n)
		}
	}
}
