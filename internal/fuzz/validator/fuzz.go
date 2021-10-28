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

// Package fuzz implements go-fuzz fuzzing functions for the validator.go file.
// See https://github.com/dvyukov/go-fuzz
package fuzz

import (
	"context"
	"fmt"

	"github.com/GoogleCloudPlatform/config-validator/pkg/api/validator"
	"github.com/GoogleCloudPlatform/config-validator/pkg/gcv"
	"github.com/gogo/protobuf/jsonpb"
)

const (
	testRoot        = "../../../test/cf"
	localPolicyDir  = testRoot
	localLibraryDir = testRoot + "/library"
)

var vdt *gcv.Validator

// Initialize the validator only once, then reuse it across Fuzz invocations.
func init() {
	var err error
	vdt, err = gcv.NewValidator([]string{localPolicyDir}, localLibraryDir)
	if err != nil {
		panic(fmt.Sprintf("unexpected error creating validator: %v", err))
	}
}

// Fuzz fuzzes reviewing assets.
func Fuzz(data []byte) (score int) {
	// Try interpreting data as an Asset.
	// Exit early if invalid.
	assetJSON := string(data)
	var asset *validator.Asset
	if err := jsonpb.UnmarshalString(assetJSON, asset); err != nil {
		return 0
	}

	// Try reviewing the asset.
	// The actual findings don't matter, but it shouldn't crash.
	vdt.ReviewAsset(context.Background(), asset)

	return 1
}
