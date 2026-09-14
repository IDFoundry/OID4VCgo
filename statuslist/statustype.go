package statuslist

import "fmt"

// StatusType is a Referenced Token's status value (draft-12 §7):
// "the state, mode, condition or stage of an entity that is
// represented by the Referenced Token." Values 0x03 and 0x0B-0x0F are
// permanently reserved as application-specific; every other value not
// listed here is reserved for future IANA registration.
type StatusType uint8

const (
	// StatusValid: "the status of the Referenced Token is valid,
	// correct or legal."
	StatusValid StatusType = 0x00

	// StatusInvalid: "the status of the Referenced Token is revoked,
	// annulled, taken back, recalled or cancelled."
	StatusInvalid StatusType = 0x01

	// StatusSuspended: "the status of the Referenced Token is
	// temporarily invalid, hanging, debarred from privilege. This
	// state is usually temporary."
	StatusSuspended StatusType = 0x02
)

func (s StatusType) String() string {
	switch s {
	case StatusValid:
		return "VALID"
	case StatusInvalid:
		return "INVALID"
	case StatusSuspended:
		return "SUSPENDED"
	default:
		return fmt.Sprintf("StatusType(0x%02X)", uint8(s))
	}
}
