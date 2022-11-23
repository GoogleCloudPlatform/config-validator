package debug

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/GoogleCloudPlatform/config-validator/pkg/gcv"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:     "debug",
	Short:   "Run the config validator on a set of policies / cai data and print out any info on errors.",
	Example: `policy-tool debug --policies ./GoogleCloudPlatform/policy-library/policies --libs ./GoogleCloudPlatform/policy-library/libs --file resource.json`,
	RunE:    debugCmd,
}

var (
	flags struct {
		policies         []string
		libs             string
		files            []string
		disabledBuiltins []string
	}
)

func init() {
	Cmd.Flags().StringSliceVar(&flags.policies, "policies", nil, "Path to one or more policy directories or files.")
	Cmd.Flags().StringVar(&flags.libs, "libs", "", "Path to the Rego libs directory.")
	Cmd.Flags().StringSliceVar(&flags.files, "file", nil, "Files to process.")
	Cmd.Flags().StringSliceVar(&flags.disabledBuiltins, "disabledBuiltins", nil, "Built in functions that should be disabled.")
	if err := Cmd.MarkFlagRequired("policies"); err != nil {
		panic(err)
	}
}

func debugCmd(cmd *cobra.Command, args []string) error {
	validator, err := gcv.NewValidator(flags.policies, flags.libs, gcv.DisableBuiltins(flags.disabledBuiltins...))
	if err != nil {
		fmt.Printf("Errors Loading Policies:\n%s\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// TODO: streaming read
	for _, fileName := range flags.files {
		fileBytes, err := ioutil.ReadFile(fileName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read %s: %v\n", fileName, err)
			continue
		}
		lines := strings.Split(string(fileBytes), "\n")
		for idx, line := range lines {
			if len(line) == 0 {
				continue
			}
			result, err := validator.ReviewJSON(ctx, line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error processing input at %s[%d]: %v\n", fileName, idx, err)
				continue
			}
			vs, err := result.ToViolations()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error processing violations for input at %s[%d]: %v\n", fileName, idx, err)
				continue
			}
			for _, v := range vs {
				fmt.Printf("%s: %s [%s]\n", v.Resource, v.Message, v.Constraint)
			}
		}
	}
	return nil
}
