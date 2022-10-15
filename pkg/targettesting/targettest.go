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

package targettesting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/GoogleCloudPlatform/config-validator/pkg/gcv/configs"
)

// defaultConstraintTemplate will fail or pass a resource depending on the
// constraint's configuration.  This does not actually inspect the object
// being reviewed.

const defaultConstraintTemplateRego = `
package testconstraint

violation[{"msg": msg}] {
	input.parameters.fail == true
	msg := input.parameters.msg
}
`

const testVersion = "v1beta1"
const testConstraintKind = "TestConstraint"

func newConstraintTemplate(targetName, rego string) *templates.ConstraintTemplate {
	// Building a correct constraint template is difficult based on the struct. It's easier
	// to reason about yaml files and rely on existing conversion code.
	ctSpec := map[string]interface{}{
		"crd": map[string]interface{}{
			"spec": map[string]interface{}{
				"names": map[string]interface{}{
					"kind": testConstraintKind,
				},
				"validation": map[string]interface{}{
					"openAPIV3Schema": map[string]interface{}{
						"type": "object",
					},
				},
			},
		},
		"targets": []map[string]interface{}{
			{
				"target": targetName,
				"rego":   rego,
			},
		},
	}
	ct := map[string]interface{}{
		"apiVersion": fmt.Sprintf("templates.gatekeeper.sh/%s", testVersion),
		"kind":       "ConstraintTemplate",
		"metadata": map[string]interface{}{
			"name": strings.ToLower(testConstraintKind),
		},
		"spec": ctSpec,
	}

	config, err := configs.NewConfigurationFromContents([]*unstructured.Unstructured{&unstructured.Unstructured{Object: ct}}, []string{})
	if err != nil {
		// This represents an error in a test case
		panic(err)
	}

	var templates []*templates.ConstraintTemplate
	templates = append(templates, config.GCPTemplates...)
	templates = append(templates, config.K8STemplates...)
	templates = append(templates, config.TFTemplates...)

	return templates[0]
}

func CreateTargetHandler(t *testing.T, target client.TargetHandler, tcs []*ReviewTestcase) *TargetHandlerTest {
	var targetHandlerTest = TargetHandlerTest{
		NewTargetHandler: func(t *testing.T) client.TargetHandler {
			return target
		},
	}
	targetHandlerTest.ReviewTestcases = tcs

	return &targetHandlerTest
}

// FromJSON returns a function that will unmarshal the JSON string and handle
// errors appropriately.
func FromJSON(data string) func(t *testing.T) interface{} {
	return func(t *testing.T) interface{} {
		t.Helper()
		var item interface{}
		if err := json.Unmarshal([]byte(data), &item); err != nil {
			t.Fatal(err)
		}
		return item
	}
}

// TargetHandlerTest is a test harness for target handler
type TargetHandlerTest struct {
	// NewTargetHandler returns a new target handler.  This should call t.Helper()
	// and t.Fatal() on any errors encountered during creation.
	NewTargetHandler func(t *testing.T) client.TargetHandler

	// ReviewTestcases are the testcases that will be run against client.Review.
	ReviewTestcases []*ReviewTestcase
}

// Test runs all testcases in the TargetHandlerTest
func (tt *TargetHandlerTest) Test(t *testing.T) {
	t.Helper()

	targetName := tt.NewTargetHandler(t).GetName()
	testBase := testcaseBase{
		newTargetHandler: tt.NewTargetHandler,
		targetName:       targetName,
		constraintTemplate: newConstraintTemplate(
			targetName,
			defaultConstraintTemplateRego,
		),
	}

	t.Run("matching_constraints", func(t *testing.T) {
		for _, tc := range tt.ReviewTestcases {
			tc.testcaseBase = testBase
			t.Run(tc.Name, tc.run)
		}
	})
}

// testcaseBase contains params that are populated by the top level test
type testcaseBase struct {
	newTargetHandler   func(t *testing.T) client.TargetHandler
	targetName         string
	constraintTemplate *templates.ConstraintTemplate
}

// ReviewTestcase exercises the TargetHandler's HandleReview and Library
// matching_constraints functions.
type ReviewTestcase struct {
	testcaseBase // stuff filled in by the test framework

	Name                string                         // Name of the testcase
	Match               map[string]interface{}         // Constraint's Match block
	Object              func(t *testing.T) interface{} // function which returns an Object that's getting passed to the Review call
	WantMatch           bool                           // true if the match should succeed
	WantConstraintError bool                           // true if adding the constraint should fail
	WantLogged          *regexp.Regexp                 // regexp to check against logged messages
}

// Run will set up the client with the TargetHandler and a test constraint template
// and constraint then run review.
func (tc *ReviewTestcase) run(t *testing.T) {
	// matching_constraints needs differing constraints for the match blocks,
	// to get test coverage, this gets exercised on calls to client.Review
	ctx := context.Background()

	var logOutput bytes.Buffer
	log.SetOutput(&logOutput)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	// create client
	cfClient := createClient(t, tc.newTargetHandler)

	// add template
	resp, err := cfClient.AddTemplate(ctx, tc.constraintTemplate)
	if err != nil {
		t.Fatalf("loading template %v: %v", tc.constraintTemplate, err)
	}
	if !resp.Handled[tc.targetName] {
		t.Fatal("expected target name")
	}

	// Create synthetic constraint
	constraintSpec := map[string]interface{}{
		"parameters": map[string]interface{}{
			"fail": true,
			"msg":  "it matched",
		},
	}
	if tc.Match != nil {
		constraintSpec["match"] = tc.Match
	}
	constraint := map[string]interface{}{
		"apiVersion": "constraints.gatekeeper.sh/v1beta1",
		"kind":       testConstraintKind,
		"metadata": map[string]interface{}{
			"name": strings.ToLower(testConstraintKind),
		},
		"spec": constraintSpec,
	}

	resp, err = cfClient.AddConstraint(ctx, &unstructured.Unstructured{Object: constraint})

	if tc.WantConstraintError {
		if err == nil {
			t.Fatal("expected constraint add error, got none")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Handled[tc.targetName] {
		t.Fatal("expected target name")
	}

	// create review from tc, input needs to be GCP hierarchy path
	reviewObj := tc.Object(t)
	resp, err = cfClient.Review(ctx, reviewObj, client.Tracing(true))
	if err != nil {
		t.Fatal(err)
	}
	review, ok := resp.ByTarget[tc.targetName]
	if !ok {
		t.Fatal("expected target name in reviews")
	}

	if tc.WantMatch {
		if len(review.Results) != 1 {
			unitTestTraceDump(t, review)
			t.Logf("match block: %v", tc.Match)
			t.Fatalf("expected exactly one results in review, got %d", len(review.Results))
		}
	} else {
		if len(review.Results) != 0 {
			unitTestTraceDump(t, review)
			t.Logf("match block: %v", tc.Match)
			t.Fatalf("unexpected results in review")
		}
	}

	if tc.WantLogged != nil {
		if !tc.WantLogged.Match(logOutput.Bytes()) {
			t.Fatalf("expected log output to match %s; got %s", tc.WantLogged.String(), logOutput.String())
		}
	}
}

func unitTestTraceDump(t *testing.T, review *types.Response) {
	t.Helper()
	// t.Logf("Trace:\n%s", *review.Trace)
	t.Logf("Target: %s", review.Target)
	t.Logf("Input:\n%s", *review.Input)
	t.Logf("Results(%d)", len(review.Results))
	for idx, result := range review.Results {
		t.Logf("  %d:\n%#v", idx, spew.Sdump(result))
	}
}

func createClient(t *testing.T, newTargetHandler func(t *testing.T) client.TargetHandler) *client.Client {
	t.Helper()
	target := newTargetHandler(t)
	if target == nil {
		t.Fatalf("newTargetHandler returned nil")
	}
	driver := local.New(local.Tracing(true))
	backend, err := client.NewBackend(client.Driver(driver))
	if err != nil {
		t.Fatalf("Could not initialize backend: %s", err)
	}
	cfClient, err := backend.NewClient(client.Targets(target))
	if err != nil {
		t.Fatalf("unable to set up OPA client: %s", err)
	}
	return cfClient
}
