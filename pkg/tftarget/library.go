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

package tftarget

import "text/template"

/*
This comment puts the start of rego on line 10 so it's easier to do math when
it calls out the line number.
*/
const libraryTemplateSrc = `package target

matching_constraints[constraint] {
	resource := input.review
	constraint := {{.ConstraintsRoot}}[_][_]
	spec := object.get(constraint, "spec", {})
	match := object.get(spec, "match", {})

	check_address(resource, match)
}

check_address(resource, match) {
	# Default matcher behavior is to match everything.
	include := object.get(match, "addresses", ["**"])
	include_match := {resource.address | path_matches(resource.address, include[_])}
	count(include_match) != 0

	exclude := object.get(match, "excludedAddresses", [])
	exclusion_match := {resource.address | path_matches(resource.address, exclude[_])}
	count(exclusion_match) == 0
}

# CAI Resource Types
matching_reviews_and_constraints[[review, constraint]] {
	# This code should not get executed as we do not yet support full audit mode
	review := {"msg": "unsupported operation"}
	constraint := {
		"msg": "unsupported operation",
		"kind": "invalid",
	}
}

autoreject_review[rejection] {
	false
	rejection := {
		"msg": "should not reach this",
	}
}

# Match path and pattern
path_matches(path, pattern) {
	glob.match(pattern, ["."], path)
}

`

var libraryTemplate = template.Must(template.New("Library").Parse(libraryTemplateSrc))
