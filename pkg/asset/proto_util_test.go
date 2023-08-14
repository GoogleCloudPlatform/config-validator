// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package asset

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestCleanProtoValues(t *testing.T) {
	cases := []struct {
		name  string
		value *structpb.Value
		noop  bool
	}{
		{
			name:  "Empty",
			value: &structpb.Value{},
			noop:  false,
		},
		{
			name: "Null",
			value: &structpb.Value{
				Kind: &structpb.Value_NullValue{},
			},
			noop: true,
		},
		{
			name: "Number",
			value: &structpb.Value{
				Kind: &structpb.Value_NumberValue{NumberValue: 0},
			},
			noop: true,
		},
		{
			name: "String",
			value: &structpb.Value{
				Kind: &structpb.Value_StringValue{StringValue: ""},
			},
			noop: true,
		},
		{
			name: "Bool",
			value: &structpb.Value{
				Kind: &structpb.Value_BoolValue{BoolValue: false},
			},
			noop: true,
		},
		{
			name: "ListNilListValue",
			value: &structpb.Value{
				Kind: &structpb.Value_ListValue{
					ListValue: nil,
				},
			},
			noop: true,
		},
		{
			name: "ListNilValues",
			value: &structpb.Value{
				Kind: &structpb.Value_ListValue{
					ListValue: &structpb.ListValue{
						Values: nil,
					},
				},
			},
			noop: true,
		},
		{
			name: "ListLen0",
			value: &structpb.Value{
				Kind: &structpb.Value_ListValue{
					ListValue: &structpb.ListValue{
						Values: []*structpb.Value{},
					},
				},
			},
			noop: true,
		},
		{
			name: "ListWithBadValue",
			value: &structpb.Value{
				Kind: &structpb.Value_ListValue{
					ListValue: &structpb.ListValue{
						Values: []*structpb.Value{
							{},
						},
					},
				},
			},
			noop: false,
		},
		{
			name: "StructNilStructValue",
			value: &structpb.Value{
				Kind: &structpb.Value_StructValue{
					StructValue: nil,
				},
			},
			noop: true,
		},
		{
			name: "StructNilValues",
			value: &structpb.Value{
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: nil,
					},
				},
			},
			noop: true,
		},
		{
			name: "StructLen0",
			value: &structpb.Value{
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: map[string]*structpb.Value{},
					},
				},
			},
			noop: true,
		},
		{
			name: "StructWithBadValue",
			value: &structpb.Value{
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"bad": {},
						},
					},
				},
			},
			noop: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pre, err := protojson.Marshal(c.value)
			if err == nil && !c.noop {
				t.Fatal("this test should have failed before calling CleanProtoValue()")
			}

			CleanProtoValue(c.value)
			post, err := protojson.Marshal(c.value)
			if err != nil {
				t.Fatal(err)
			}

			if c.noop && !bytes.Equal(pre, post) {
				t.Fatalf("expected no-op, found difference in json output: pre: %s\npost: %s\n", pre, post)
			}
		})
	}
}
