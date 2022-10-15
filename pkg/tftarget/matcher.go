// Copyright 2022 Google LLC
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

package tftarget

import (
	"fmt"

	"github.com/gobwas/glob"
)

type matcher struct {
	include []string
	exclude []string
}

var ErrInvalidReview = fmt.Errorf("unexpected type of review, expect map[string]interface{}")
var ErrInvalidAddress = fmt.Errorf("unexpected type of address in review object")

// Match returns true if the Matcher's Constraint should run against the
// passed review object.
func (m *matcher) Match(review interface{}) (bool, error) {
	reviewObj, ok := review.(map[string]interface{})
	if !ok {
		return false, ErrInvalidReview
	}
	address, ok := reviewObj["address"].(string)
	if !ok {
		return false, ErrInvalidAddress
	}

	matched := false
	for _, pattern := range m.include {
		g := glob.MustCompile(pattern, '.')
		if g.Match(address) {
			matched = true
			break
		}
	}
	if !matched {
		return false, nil
	}

	for _, pattern := range m.exclude {
		g := glob.MustCompile(pattern, '.')
		if g.Match(address) {
			return false, nil
		}
	}
	return true, nil
}
