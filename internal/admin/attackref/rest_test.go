// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package attackref

import (
	"context"
	"testing"
	"time"
)

func TestMinerRestIsProportionalToTheReadAndCancellable(t *testing.T) {
	m := &Miner{Cfg: Config{Rest: 1}}

	start := time.Now()
	m.rest(context.Background(), time.Now().Add(-200*time.Millisecond))
	if d := time.Since(start); d < 150*time.Millisecond || d > time.Second {
		t.Errorf("repos de %v après une lecture de 200 ms, attendu ~200 ms", d)
	}

	m.Cfg.Rest = 0
	start = time.Now()
	m.rest(context.Background(), time.Now().Add(-time.Second))
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("repos de %v alors que Rest vaut 0", d)
	}

	m.Cfg.Rest = 1
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	m.rest(ctx, time.Now().Add(-5*time.Second))
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("repos de %v malgré un contexte annulé", d)
	}
}
