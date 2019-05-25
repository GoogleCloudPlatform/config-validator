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

package cf

const AuditRego = `
package validator.gcp.lib

# Audit endpoint to grab all violations found in data.constraints

audit[result] {
	inventory := data.inventory
	constraints := data.constraints

	asset := inventory[_]
	constraint := constraints[_]
	
	re_match(constraint.spec.match.gcp.target[_], asset.ancestry_path)
	exclusion_match := {asset.ancestry_path | re_match(constraint.spec.match.gcp.exclude[_], asset.ancestry_path)}
	count(exclusion_match) == 0

	violations := data.templates.gcp[constraint.kind].deny with input.asset as asset
		 with input.constraint as constraint

	violation := violations[_]

	result := {
		"asset": asset.name,
		"constraint": constraint.metadata.name,
		"violation": violation,
	}
}
`
