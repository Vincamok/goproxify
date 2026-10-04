package main

import (
	"reflect"
	"testing"
)

func TestPositionalArgs(t *testing.T) {
	got := positionalArgs([]string{"7", "-token", "abc", "maintenance", `{"enabled":true}`, "-admin-url", "http://x"})
	want := []string{"7", "maintenance", `{"enabled":true}`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("positionalArgs = %q, attendu %q", got, want)
	}
}
