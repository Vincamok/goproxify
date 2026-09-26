package api

import "testing"

func TestBanTechnique(t *testing.T) {
	cases := []struct{ src, reason, key, label string }{
		{"threat", "threat: path", "path", "Chemin sensible (scan)"},
		{"threat", "threat: rate", "rate", "Débit excessif"},
		{"fail2ban", "Fail2Ban: trop d'erreurs", "errors", "Trop d'erreurs HTTP"},
		{"crowdsec", "crowdsecurity/http-probing", "crowdsecurity/http-probing", "crowdsecurity/http-probing"},
		{"native", "", "unknown", "Non précisé"},
	}
	for _, c := range cases {
		k, l := banTechnique(c.src, c.reason)
		if k != c.key || l != c.label {
			t.Errorf("%s/%q = %q,%q ; attendu %q,%q", c.src, c.reason, k, l, c.key, c.label)
		}
	}
}
