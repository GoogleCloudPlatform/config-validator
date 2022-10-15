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

package gcptarget

import (
	"fmt"

	"github.com/gobwas/glob"
)

var ErrInvalidReview = fmt.Errorf("unexpected type of review, expect map[string]interface{}")
var ErrInvalidAncestryPath = fmt.Errorf("unexpected type of ancestry path in review object")

type matcher struct {
	include []string
	exclude []string
}

func (m *matcher) Match(review interface{}) (bool, error) {
	reviewObj, ok := review.(map[string]interface{})
	if !ok {
		return false, ErrInvalidReview
	}
	ancestryPath, ok := reviewObj["ancestry_path"].(string)
	if !ok {
		return false, ErrInvalidAncestryPath
	}

	matchAncestries := false
	for _, pattern := range m.include {
		g := glob.MustCompile(pattern, '/')
		if g.Match(ancestryPath) {
			matchAncestries = true
			break
		}
	}
	if !matchAncestries {
		return false, nil
	}

	for _, pattern := range m.exclude {
		g := glob.MustCompile(pattern, '/')
		if g.Match(ancestryPath) {
			return false, nil
		}
	}
	return true, nil
}
