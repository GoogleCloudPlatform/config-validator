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
	spec := _get_default(constraint, "spec", {})
	match := _get_default(spec, "match", {})

	check_provider(resource)
	check_address(resource, match)
}

check_provider(resource) {
	_has_field(resource, "provider_name")
	contains(resource.provider_name, "google")
}

check_provider(resource) {
	not _has_field(resource, "provider_name")
}

check_address(resource, match) {
	# Default matcher behavior is to match everything.
	include := _get_default(match, "addresses", ["**"])
	include_match := {resource.address | path_matches(resource.address, include[_])}
	count(include_match) != 0

	exclude := _get_default(match, "excludedAddresses", [])
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

########
# Util #
########
# The following functions are prefixed with underscores, because their names
# conflict with the existing functions in policy library. We want to separate
# them here to ensure that there is no dependency or confusion.

# _get_default returns the value of an object's field or the provided default value.
# It avoids creating an undefined state when trying to access an object attribute that does
# not exist
_get_default(object, field, _default) = output {
  _has_field(object, field)
  output = object[field]
}

_get_default(object, field, _default) = output {
  _has_field(object, field) == false
  output = _default
}

# _has_field returns whether an object has a field
_has_field(object, field) = true {
  object[field]
}
# False is a tricky special case, as false responses would create an undefined document unless
# they are explicitly tested for
_has_field(object, field) = true {
  object[field] == false
}
_has_field(object, field) = false {
  not object[field]
  not object[field] == false
}

`

var libraryTemplate = template.Must(template.New("Library").Parse(libraryTemplateSrc))
