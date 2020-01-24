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
	_, err := gcv.NewValidator(make(chan struct{}), flags.policies, flags.libs)
	if err != nil {
		fmt.Printf("linter errors:\n%s\n", err)
		os.Exit(1)
	}
	fmt.Printf("No lint errors found.\n")
	return nil
}
