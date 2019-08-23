package status

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/forseti-security/config-validator/pkg/bundlemanager"
)

var Cmd = &cobra.Command{
	Use:     "status",
	Short:   "Print the status of the policy library's constraint templates and bundles.",
	Example: `policy-tool status --path ./forseti-security/policy-library/policies`,
	RunE:    statusCmd,
}

var (
	path string
)

func init() {
	Cmd.Flags().StringVar(&path, "path", "", "Path to the policies directory.")
	Cmd.MarkFlagRequired("path")
}

func statusCmd(cmd *cobra.Command, args []string) error {
	bundleManager := bundlemanager.New()
	if err := bundleManager.Load(path); err != nil {
		return err
	}

	bundles := bundleManager.Bundles()
	for _, bundle := range bundles {
		controls := bundleManager.Controls(bundle)
		fmt.Printf("bundle: %s\n", bundle)
		for _, control := range controls {
			fmt.Printf(" control: %s\n", control)
		}
	}

	for _, obj := range bundleManager.All() {
		var unknown []string
		for k, v := range obj.GetAnnotations() {
			if !bundlemanager.HasBundleAnnotation(k) {
				unknown = append(unknown, fmt.Sprintf("%s=%s", k, v))
			}
		}
		if 0 != len(unknown) {
			fmt.Printf("resource %s has unknown annotations\n", obj.GetName())
			for _, v := range unknown {
				fmt.Printf("  %s\n", v)
			}
		}
	}

	unbundled := bundleManager.Unbundled()
	if len(unbundled) != 0 {
		fmt.Printf("unbundled constraint templates\n")
		for _, unbundled := range bundleManager.Unbundled() {
			fmt.Printf("  %s\n", unbundled)
		}
	}
	return nil
}
