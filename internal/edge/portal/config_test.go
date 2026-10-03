package portal

import "testing"

func TestNormalizeTheme(t *testing.T) {
	for in, want := range map[string]string{"": "auto", "Sombre": "sombre", " ocean ": "ocean", "bogus": "auto", "contraste": "contraste"} {
		if got := NormalizeTheme(in); got != want {
			t.Errorf("NormalizeTheme(%q) = %q, want %q", in, got, want)
		}
	}
}
