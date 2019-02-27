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

package gcv

import (
	"testing"
)

// TODO(corb): add more tests
//  Errors
//    No dir
//    Invalid dir
//    No config files
//    No read access

const (
	localPolicyDir = "../../../policies/"
)

func TestCreateValidatorWithNoOptions(t *testing.T) {
	_, err := NewValidator()
	if err == nil {
		t.Fatal("Expected an error since no policy path is provided")
	}
}

func TestDefaultTestDataCreatesValidator(t *testing.T) {
	_, err := NewValidator(generateDefaultTestOptions())
	if err != nil {
		t.Fatal("Unexpected Error", err)
	}
}

// groupOptions will Groups options in order into a single option.
func groupOptions(options ...Option) Option {
	return func(v *Validator) error {
		for _, option := range options {
			if err := option(v); err != nil {
				return err
			}
		}
		return nil
	}
}

// generateDefaultTestOptions provides a set of default options that allows the successful creation
// of a validator.
func generateDefaultTestOptions() Option {
	// Add default options to this list
	return groupOptions(
		PolicyPath(localPolicyDir),
	)
}
