package verifierapp

import "testing"

// Each page state maps to the coarse state the status endpoint reports,
// an answer winning over the rest.
func TestPageState_Coarse(t *testing.T) {
	for _, tc := range []struct {
		st   pageState
		want string
	}{
		{pageState{}, stateWaiting},
		{pageState{lastError: "bad"}, stateWaiting},
		{pageState{awaiting: true}, stateAwaiting},
		{pageState{closed: true, lastError: "bad"}, stateClosed},
		{pageState{outcome: &Outcome{}, awaiting: true}, stateAnswered},
	} {
		if got := tc.st.coarse(); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.st, got, tc.want)
		}
	}
}
