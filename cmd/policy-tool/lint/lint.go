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

package lint

import (
	"fmt"
	"os"

	"github.com/forseti-security/config-validator/pkg/gcv"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:     "lint",
	Short:   "Lint a directory containing ConstraintTemplates and/or Constraints.",
	Example: `policy-tool status --policies ./forseti-security/policy-library/policies --libs ./forseti-security/policy-library/libs`,
	RunE:    lintCmd,
}

var (
	flags struct {
		policies []string
		libs     string
	}
)

func init() {
	Cmd.Flags().StringSliceVar(&flags.policies, "policies", nil, "Path to one or more policies directories.")
	Cmd.Flags().StringVar(&flags.libs, "libs", "", "Path to the libs directory.")
	if err := Cmd.MarkFlagRequired("policies"); err != nil {
		panic(err)
	}
}

func lintCmd(cmd *cobra.Command, args []string) error {
	_, err := gcv.NewValidator(flags.policies, flags.libs)
	if err != nil {
		fmt.Printf("linter errors:\n%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("No lint errors found.\n")
	return nil
}
