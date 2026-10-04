// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package grpctrans

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func anypbNew(m proto.Message) ([]*anypb.Any, error) {
	a, err := anypb.New(m)
	if err != nil {
		return nil, err
	}
	return []*anypb.Any{a}, nil
}
