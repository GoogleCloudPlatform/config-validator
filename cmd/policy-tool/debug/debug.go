package debug

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/forseti-security/config-validator/pkg/gcv"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:     "debug",
	Short:   "Run the config validator on a set of policies / cai data and print out any info on errors.",
	Example: `policy-tool debug --policies ./forseti-security/policy-library/policies --libs ./forseti-security/policy-library/libs --file resource.json`,
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
	Cmd.Flags().StringSliceVar(&flags.policies, "policies", nil, "Path to one or more policies directories.")
	Cmd.Flags().StringVar(&flags.libs, "libs", "", "Path to the libs directory.")
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
			fmt.Printf("Failed to read %s: %s\n", fileName, err)
			continue
		}

		lines := strings.Split(string(fileBytes), "\n")
		for idx, line := range lines {
			_, err := validator.ReviewJSON(ctx, line)
			if err != nil {
				fmt.Printf("Error processing line %d: %s\nValue: %s\n", idx, err, line)
			}
		}
	}
	return nil
}
