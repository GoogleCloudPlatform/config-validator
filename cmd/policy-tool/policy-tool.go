package main

import (
	"flag"
	"fmt"
	"os"

	_ "github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/forseti-security/config-validator/cmd/policy-tool/lint"
	"github.com/forseti-security/config-validator/cmd/policy-tool/status"
)

var (
	rootCmd = &cobra.Command{
		Use:   "policy-tool",
		Short: "Tool for managing constraint template bundles.",
	}
)

var glogFlags = map[string]struct{}{
	"alsologtostderr":  {},
	"log_backtrace_at": {},
	"log_dir":          {},
	"logtostderr":      {},
	"stderrthreshold":  {},
	"v":                {},
	"vmodule":          {},
}

func init() {
	rootCmd.AddCommand(status.Cmd)
	rootCmd.AddCommand(lint.Cmd)
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if _, ok := glogFlags[f.Name]; ok {
			pflag.CommandLine.AddGoFlag(f)
		}
	})
}

func main() {
	// glog complains if we don't parse flags
	args := os.Args
	os.Args = os.Args[0:1]
	flag.Parse()
	os.Args = args

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("%#v\n", err)
		os.Exit(1)
	}
}
