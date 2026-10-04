package admin

import "testing"

func TestParseCgroupLimit(t *testing.T) {
	for raw, want := range map[string]struct {
		n  int64
		ok bool
	}{
		"max\n":                 {0, false},
		"":                      {0, false},
		"536870912\n":           {536870912, true},
		"9223372036854771712\n": {0, false}, // cgroup v1 sans limite
		"abc":                   {0, false},
		"-1":                    {0, false},
	} {
		if n, ok := parseCgroupLimit(raw); n != want.n || ok != want.ok {
			t.Errorf("%q → %d,%v (attendu %d,%v)", raw, n, ok, want.n, want.ok)
		}
	}
}
