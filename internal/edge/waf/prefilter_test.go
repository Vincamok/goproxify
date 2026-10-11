// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

var attackSeeds = []string{
	"1 UNION SELECT password FROM users", "' OR '1'='1", "'; DROP TABLE users--", "<script>alert(1)</script>",
	"<img src=x onerror=alert(1)>", "javascript:alert(1)", "../../etc/passwd", "..%2f..%2fetc/passwd", "/etc/shadow",
	"; cat /etc/passwd", "| whoami", "$(id)", "`uname -a`", "${jndi:ldap://x/a}", "{{7*7}}", "<?php system($_GET[1]); ?>",
	"http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", "sqlmap/1.5", "Nikto", "Runtime.getRuntime().exec(x)",
	"rO0ABQAAAAAAAAAAAAAAAAAAAAAAAAAAA", "php://filter/convert.base64-encode/resource=x", "__proto__", "require('child_process')",
	"Transfer-Encoding: chunked\r\nContent-Length: 4", "/.git/config", "/wp-config.php", "x\r\nContent-Type: text/html",
	"Fatal error: in /var/www/x.php on line 3", "ORA-00933: SQL command", "benchmark(1000000,md5(1))", "waitfor delay '0:0:5'",
	"SLEEP(5)", "UNİON SELECT", "ſelect * from users", "unionKselect", "café crème", "bonjour le monde",
}

func mutate(rng *rand.Rand, s string) string {
	b := []rune(s)
	for i := range b {
		if rng.Intn(3) == 0 {
			if rng.Intn(2) == 0 {
				b[i] = []rune(strings.ToUpper(string(b[i])))[0]
			} else {
				b[i] = []rune(strings.ToLower(string(b[i])))[0]
			}
		}
	}
	pad := []string{"", " ", "x", "%20", "\n", "é", "ſ"}
	return pad[rng.Intn(len(pad))] + string(b) + pad[rng.Intn(len(pad))]
}

// Le pré-filtre ne doit jamais écarter une valeur que la règle reconnaîtrait : pour toute règle et toute valeur,
// « le motif reconnaît » implique « le pré-filtre laisse passer ».
func TestPrefilter_NeverHidesAMatch(t *testing.T) {
	rules := DefaultRules()
	rng := rand.New(rand.NewSource(1))
	var corpus []string
	for _, s := range attackSeeds {
		corpus = append(corpus, s)
		for i := 0; i < 40; i++ {
			corpus = append(corpus, mutate(rng, s))
		}
	}
	for _, r := range rules {
		for _, lit := range r.required {
			for i := 0; i < 20; i++ {
				corpus = append(corpus, mutate(rng, "x "+lit+" y"), mutate(rng, strings.ToUpper(lit)+"("))
			}
		}
	}
	filtered := 0
	for _, r := range rules {
		r := r
		if r.required != nil {
			filtered++
		}
		for _, v := range corpus {
			lo, ok := lowered(v)
			if r.Pattern.MatchString(v) && !r.mayMatch(lo, ok) {
				t.Fatalf("règle %d : le pré-filtre %q écarte %q que le motif reconnaît", r.ID, r.required, v)
			}
		}
	}
	if filtered < len(rules)/2 {
		t.Errorf("seulement %d règles sur %d ont un pré-filtre : l'extraction des littéraux est trop timide", filtered, len(rules))
	}
}

func TestRequiredLiterals(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		want    []string
	}{
		{`(?i)union[\s]+select`, []string{"union"}}, // l'ensemble le plus sélectif : « select » vaut « union »
		{`(?i)(?:nikto|sqlmap)`, []string{"nikto", "sqlmap"}},
		{`(?i)abc|[0-9]+`, nil},       // une branche sans littéral : pas de pré-filtre
		{`[a-z]+`, nil},               // aucun littéral
		{`(?i)é+`, nil},               // littéral non ASCII
		{`(?:foo)?bar`, []string{"bar"}},
		{`x*`, nil},
	} {
		got := requiredLiterals(tc.pattern)
		if tc.pattern == `(?i)union[\s]+select` {
			if len(got) != 1 || (got[0] != "union" && got[0] != "select") {
				t.Errorf("%s → %q", tc.pattern, got)
			}
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s → %q, attendu %q", tc.pattern, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s → %q, attendu %q", tc.pattern, got, tc.want)
			}
		}
	}
}

func TestLowered_SkipsFoldSensitiveValues(t *testing.T) {
	if _, ok := lowered("ſelect"); ok {
		t.Error("ſ se confond avec s : la valeur ne peut pas être pré-filtrée")
	}
	if _, ok := lowered("unionKselect"); ok {
		t.Error("K Kelvin se confond avec k")
	}
	if lo, ok := lowered("Café SELECT"); !ok || lo != "café select" {
		t.Errorf("lowered = %q %v", lo, ok)
	}
}

// Le résultat d'une inspection est le même avec et sans pré-filtre.
func TestPrefilter_InspectResultsUnchanged(t *testing.T) {
	with := NewEngine(nil, nil)
	without := NewEngine(nil, nil)
	for i := range without.rules {
		without.rules[i].required = nil
	}
	rng := rand.New(rand.NewSource(7))
	for _, s := range attackSeeds {
		for i := 0; i < 25; i++ {
			v := mutate(rng, s)
			for _, target := range []string{"/x?q=" + v, "/" + v} {
				r1 := httptestRequest(target)
				r2 := httptestRequest(target)
				a, b := with.Inspect(r1, 1), without.Inspect(r2, 1)
				if len(a) != len(b) {
					t.Fatalf("%q : %d règles avec pré-filtre, %d sans", target, len(a), len(b))
				}
				for k := range a {
					if a[k].RuleID != b[k].RuleID {
						t.Fatalf("%q : règles différentes %v / %v", target, a, b)
					}
				}
			}
		}
	}
}

func httptestRequest(target string) *http.Request {
	r, err := http.NewRequest(http.MethodGet, "http://x.test/", nil)
	if err != nil {
		panic(err)
	}
	u, err := url.Parse("http://x.test" + escapeForTest(target))
	if err != nil {
		panic(err)
	}
	r.URL = u
	return r
}

func escapeForTest(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c <= 0x20 || c >= 0x7f || c == '#' {
			b.WriteString(url.QueryEscape(string([]byte{c})))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
