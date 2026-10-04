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

func TestParseMemTotal(t *testing.T) {
	info := "MemTotal:        2021084 kB\nMemFree:          67584 kB\n"
	if n, ok := parseMemTotal(info); !ok || n != 2021084<<10 {
		t.Fatalf("MemTotal : %d %v", n, ok)
	}
	for _, bad := range []string{"", "MemFree: 1 kB\n", "MemTotal: abc kB\n", "MemTotal:\n"} {
		if _, ok := parseMemTotal(bad); ok {
			t.Fatalf("%q accepté", bad)
		}
	}
}
