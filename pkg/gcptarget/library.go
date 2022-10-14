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

package gcptarget

import "text/template"

/*
This comment puts the start of rego on line 10 so it's easier to do math when
it calls out the line number.
*/
const libraryTemplateSrc = `package target

matching_constraints[constraint] {
	asset := input.review
	constraint := {{.ConstraintsRoot}}[_][_]
	spec := object.get(constraint, "spec", {})
	match := object.get(spec, "match", {})

	# Try ancestries / excludedAncestries first, then
	# fall back to target / exclude.
	# Default matcher behavior is to match everything.
	ancestries := object.get(match, "ancestries", object.get(match, "target", ["**"]))
	ancestries_match := {asset.ancestry_path | path_matches(asset.ancestry_path, ancestries[_])}
	count(ancestries_match) != 0

	excluded_ancestries := object.get(match, "excludedAncestries", object.get(match, "exclude", []))
	excluded_ancestries_match := {asset.ancestry_path | path_matches(asset.ancestry_path, excluded_ancestries[_])}
	count(excluded_ancestries_match) == 0
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
	glob.match(pattern, ["/"], path)
}

########
# Util #
########
# get_default returns the value of an object's field or the provided default value.
# It avoids creating an undefined state when trying to access an object attribute that does
# not exist
get_default(object, field, _default) = output {
  has_field(object, field)
  output = object[field]
}

get_default(object, field, _default) = output {
  has_field(object, field) == false
  output = _default
}

# has_field returns whether an object has a field
has_field(object, field) = true {
  object[field]
}
# False is a tricky special case, as false responses would create an undefined document unless
# they are explicitly tested for
has_field(object, field) = true {
  object[field] == false
}
has_field(object, field) = false {
  not object[field]
  not object[field] == false
}

`

var libraryTemplate = template.Must(template.New("Library").Parse(libraryTemplateSrc))
