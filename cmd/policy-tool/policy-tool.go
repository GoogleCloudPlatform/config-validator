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

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/GoogleCloudPlatform/config-validator/cmd/policy-tool/debug"
	"github.com/GoogleCloudPlatform/config-validator/cmd/policy-tool/lint"
	"github.com/GoogleCloudPlatform/config-validator/cmd/policy-tool/status"
	_ "github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	rootCmd.AddCommand(debug.Cmd)
	rootCmd.AddCommand(lint.Cmd)
	rootCmd.AddCommand(status.Cmd)
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
