package analytics

import "testing"
func TestDomainCond(t *testing.T) {
	cases := []struct {
		in   string
		cond string
		n    int
	}{
		{"", "", 0},
		{" , ", "", 0},
		{"a.fr", "d = ?", 1},
		{"a.fr, b.fr,", "d IN (?,?)", 2},
	}
	for _, c := range cases {
		cond, args := domainCond("d", c.in)
		if cond != c.cond || len(args) != c.n {
			t.Errorf("domainCond(%q) = %q, %d args; veut %q, %d", c.in, cond, len(args), c.cond, c.n)
		}
	}
}
