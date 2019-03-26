#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package validator.gcp.lib

import data.test.fixtures.assets as asset_fixtures

# Gather fixture assets into a flat array (for data.inventory)
all_fixture_assets[resource] {
	resource := asset_fixtures[_][_]
}

# Gather fixture constraints into a flat array (for data.constraints)
all_fixture_constraints = [
	data.test.fixtures.constraints.always_violates_all,
	data.test.fixtures.constraints.require_storage_logging,
]

# Fixture Violations
fixtures_audit[violation] {
	violations := audit with data.inventory as all_fixture_assets
		 with data.constraints as all_fixture_constraints

	violation := violations[_]
}

test_fixtures_audit {
	count(fixtures_audit) = 9
}
