// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"context"
	"strings"
	"testing"
)

func TestWebDAVDriverRefusesMetadataAddresses(t *testing.T) {
	d, err := NewDriver(Destination{Type: DestWebDAV, Config: map[string]string{"url": "http://169.254.169.254/dav"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Put(context.Background(), "x.bin", []byte("x")); err == nil || !strings.Contains(err.Error(), "refusée") {
		t.Fatalf("destination vers les métadonnées cloud jointe : %v", err)
	}
}
