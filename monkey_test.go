package monketor

import (
	"testing"
)

func TestMonketor(t *testing.T) {
	cs, err := MonkeyAround()
	if err != nil {
		t.Fatal(err)
	}

	t.Log("calls:", cs.Calls("monketor.SomeFunction"))
	SomeFunction(t)
	t.Log("calls:", cs.Calls("monketor.SomeFunction"))
}

//go:noinline
func SomeFunction(t *testing.T) {
	t.Log("I got called")
}
