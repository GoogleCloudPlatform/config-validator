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
	spec := get_default(constraint, "spec", {})
	match := get_default(spec, "match", {})

	# Default matcher behavior is to match everything.
	target := get_default(match, "target", ["**"])
  #re_match(target[_], asset.ancestry_path)
	path_matches(asset.ancestry_path, target[_])
	exclude := get_default(match, "exclude", [])
	#exclusion_match := {asset.ancestry_path | re_match(exclude[_], asset.ancestry_path)}
	exclusion_match := {asset.ancestry_path | path_matches(asset.ancestry_path, exclude[_])}
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
