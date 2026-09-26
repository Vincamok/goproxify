package edge

import "testing"

func TestBucketQuantile(t *testing.T) {
	// 100 requêtes : 50 ≤ 100 ms, 90 ≤ 500 ms, 100 ≤ 1 s
	b := map[float64]float64{0.1: 50, 0.5: 90, 1: 100}
	if got := bucketQuantile(b, 100, 30, 0.5); got != 0.1 {
		t.Errorf("p50 = %v, attendu 0.1", got)
	}
	got := bucketQuantile(b, 100, 30, 0.95)
	if got <= 0.5 || got >= 1 {
		t.Errorf("p95 = %v, attendu dans ]0.5, 1[", got)
	}
	if got := bucketQuantile(b, 0, 0, 0.95); got != 0 {
		t.Errorf("histogramme vide = %v, attendu 0", got)
	}
	if got := bucketQuantile(map[float64]float64{1: 10}, 20, 40, 0.95); got != 2 {
		t.Errorf("au-delà du dernier bucket = %v, attendu la moyenne 2", got)
	}
}
