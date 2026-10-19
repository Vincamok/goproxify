package edge

import "testing"

func TestBlockedAttrs(t *testing.T) {
	if got := blockedAttrs(0, "ip", "1.1.1.1"); len(got) != 2 {
		t.Fatalf("sans répétition : %v", got)
	}
	if got := blockedAttrs(3, "ip", "1.1.1.1"); len(got) != 4 || got[2] != "repeats" || got[3] != 3 {
		t.Fatalf("avec répétitions : %v", got)
	}
}
