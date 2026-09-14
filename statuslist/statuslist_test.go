package statuslist

import "testing"

func TestStatusType_String(t *testing.T) {
	cases := []struct {
		s    StatusType
		want string
	}{
		{StatusValid, "VALID"},
		{StatusInvalid, "INVALID"},
		{StatusSuspended, "SUSPENDED"},
		{StatusType(0x0B), "StatusType(0x0B)"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("StatusType(0x%02X).String() = %q, want %q", uint8(c.s), got, c.want)
		}
	}
}

func TestNew_RejectsInvalidBits(t *testing.T) {
	if _, err := New(Bits(3), []uint8{0}, ""); err == nil {
		t.Errorf("New accepted bits=3")
	}
}

func TestStatusList_Decode_RejectsInvalidBits(t *testing.T) {
	sl := StatusList{Bits: Bits(3), Lst: "AA"}
	if _, err := sl.Decode(); err == nil {
		t.Errorf("Decode accepted bits=3")
	}
}

func TestStatusList_New_RoundTrip(t *testing.T) {
	statuses := []uint8{0, 1, 2, 3, 0, 1, 2, 3, 0}
	sl, err := New(Bits2, statuses, "https://example.com/aggregation")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if sl.AggregationURI != "https://example.com/aggregation" {
		t.Errorf("AggregationURI = %q", sl.AggregationURI)
	}
	for idx, want := range statuses {
		got, err := sl.Status(idx)
		if err != nil {
			t.Fatalf("Status(%d): %v", idx, err)
		}
		if got != want {
			t.Errorf("Status(%d) = %d, want %d", idx, got, want)
		}
	}
}
