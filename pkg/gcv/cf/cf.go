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

import (
	"context"
	"fmt"

	"github.com/forseti-security/config-validator/pkg/api/validator"
	"github.com/forseti-security/config-validator/pkg/gcv/configs"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ConstraintFramework organizes constraints/templates/data and handles evaluation.
type ConstraintFramework struct {
	userInputData []interface{}
	// map[userDefined]regoCode
	dependencyCode map[string]string
	auditScript    string
	regoCompiler   *ast.Compiler
	regoStore      storage.Store
}

const (
	inputDataPrefix      = "inventory"
	constraintPathPrefix = "constraints"
	regoLibraryRule      = "data.validator.gcp.lib.audit"
)

// New creates a new ConstraintFramework
// args:
//   dependencyCode: map[debugString]regoCode: The debugString key will be referenced in compiler errors. It should help identify the source of the rego code.
func New(dependencyCode map[string]string) (*ConstraintFramework, error) {
	cf := ConstraintFramework{}
	_, compileErrors := ast.CompileModules(dependencyCode)
	if compileErrors != nil {
		return nil, status.Error(codes.InvalidArgument, compileErrors.Error())
	}
	cf.dependencyCode = dependencyCode
	cf.auditScript = AuditRego
	return &cf, nil
}

// AddData adds GCP resource metadata to be audited later.
func (cf *ConstraintFramework) AddData(objJSON interface{}) {
	cf.userInputData = append(cf.userInputData, objJSON)
}

// templatePkgPath constructs a package prefix based off the generated type.
func templatePkgPath(t *configs.ConstraintTemplate) string {
	return fmt.Sprintf("templates.gcp%s", t.GeneratedKind)
}

// validateTemplate verifies template compiles
func (cf *ConstraintFramework) validateTemplate(t *configs.ConstraintTemplate) error {
	// validate rego code can be compiled
	_, err := staticCompile(cf.auditScript, cf.dependencyCode, map[string]*configs.ConstraintTemplate{
		templatePkgPath(t): t,
	})
	return err
}

// Configure will set the constraint templates and constraints for ConstraintFramework
func (cf *ConstraintFramework) Configure(templates []*configs.ConstraintTemplate, constraints []*configs.Constraint) error {
	// create compiler from templates, other rego sources
	templateMap := make(map[string]*configs.ConstraintTemplate)
	for _, template := range templates {
		if _, exists := templateMap[template.GeneratedKind]; exists {
			return errors.Errorf("conflicting constraint templates with kind %s from file %s", template.GeneratedKind, template.Confg.FilePath)
		}
		if err := cf.validateTemplate(template); err != nil {
			return errors.Wrapf(err, "failed to validate template")
		}
		templateMap[template.GeneratedKind] = template
	}

	// create store from constraints
	constraintMap := make(map[string]map[string]*configs.Constraint)
	for _, c := range constraints {
		if _, ok := constraintMap[c.Confg.Kind]; !ok {
			constraintMap[c.Confg.Kind] = make(map[string]*configs.Constraint)
		}
		if _, exists := constraintMap[c.Confg.Kind][c.Confg.MetadataName]; exists {
			return errors.Errorf("Conflicting constraint metadata names with name %s from file %s", c.Confg.MetadataName, c.Confg.FilePath)
		}
		if _, exists := templateMap[c.Confg.Kind]; !exists {
			return errors.Errorf("no template found for kind %s, constraint's template needs to be loaded before constraint. ", c.Confg.Kind)
		}
		constraintMap[c.Confg.Kind][c.Confg.MetadataName] = c
	}

	compiler, err := staticCompile(cf.auditScript, cf.dependencyCode, templateMap)
	if err != nil {
		return errors.Wrapf(err, "failed to compile all templates")
	}

	constraintsData, err := constraintAsInputData(constraintMap)
	if err != nil {
		return errors.Wrapf(err, "failed to generate constraints as data")
	}

	cf.regoCompiler = compiler
	cf.regoStore = inmem.NewFromObject(map[string]interface{}{
		constraintPathPrefix: constraintsData,
	})
	return nil
}

func staticCompile(auditScript string, dependencyCode map[string]string, templates map[string]*configs.ConstraintTemplate) (*ast.Compiler, error) {
	// Use different key prefixes to ensure no collisions when joining these maps
	regoCode := make(map[string]string)

	regoCode["core.dependencies.audit"] = auditScript

	for key, depRego := range dependencyCode {
		regoCode[fmt.Sprintf("dependencies.%s", key)] = depRego
	}
	for _, template := range templates {
		key := templatePkgPath(template)
		regoCode[fmt.Sprintf("templates.%s", key)] = template.Rego
	}
	return ast.CompileModules(regoCode)
}

// Reset the user provided data, preserving the constraint and template information.
func (cf *ConstraintFramework) Reset() {
	// Clear input data
	// This is provided as a param in audit
	cf.userInputData = []interface{}{}
}

// constraintAsInputData prepares the constraint data for providing to rego.
// The rego libraries require the data to be formatted as golang objects to be parsed.
// Our audit script expects these constraints to be in a flat array.
// Input: map[kind][metadataName]constraint
// Returns: []golangNestedObject
func constraintAsInputData(constraintMap map[string]map[string]*configs.Constraint) ([]interface{}, error) {
	// mimic the same type as the input, but have a string to store the raw constraint data
	flattened := []interface{}{}

	for _, constraints := range constraintMap {
		for _, constraint := range constraints {
			structured, err := constraint.Confg.AsInterface()
			if err != nil {
				return nil, err
			}
			flattened = append(flattened, structured)
		}
	}

	return flattened, nil
}

func (cf *ConstraintFramework) buildRegoObject(ctx context.Context) (*rego.Rego, error) {
	txn, err := cf.regoStore.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return nil, err
	}

	path := storage.Path{inputDataPrefix}
	_, err = cf.regoStore.Read(ctx, txn, path)
	if err == nil {
		if err := cf.regoStore.Write(ctx, txn, storage.ReplaceOp, path, cf.userInputData); err != nil {
			return nil, err
		}
	} else if err != nil && storage.IsNotFound(err) {
		if err := cf.regoStore.Write(ctx, txn, storage.AddOp, path, cf.userInputData); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	if err := cf.regoStore.Commit(ctx, txn); err != nil {
		return nil, err
	}

	r := rego.New(
		rego.Query(regoLibraryRule),
		rego.Compiler(cf.regoCompiler),
		rego.Store(cf.regoStore))
	return r, nil
}

func auditExpressionResult(ctx context.Context, r *rego.Rego) (*rego.ExpressionValue, error) {
	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, err
	}
	if len(rs) != 1 {
		// Only expecting to receive a single result set
		return nil, status.Errorf(codes.Internal, "unexpected length of rego eval results, expected 1 got %d. This could indicate an error in the audit rego code", len(rs))
	}
	if len(rs[0].Expressions) != 1 {
		return nil, status.Errorf(codes.Internal, "unexpected length of rego Expression results, expected 1 (from audit call) got %d. This could indicate an error in the audit rego code", len(rs[0].Expressions))
	}
	expressionResult := rs[0].Expressions[0]
	if expressionResult.Text != regoLibraryRule {
		return nil, status.Errorf(codes.Internal, "Unknown expression result %s, expected %s", expressionResult.Text, regoLibraryRule)
	}

	return expressionResult, nil
}

// Audit checks the GCP resource metadata that has been added via AddData to determine if any of the constraint is violated.
func (cf *ConstraintFramework) Audit(ctx context.Context) (*validator.AuditResponse, error) {
	r, err := cf.buildRegoObject(ctx)
	if err != nil {
		return nil, err
	}

	expressionVal, err := auditExpressionResult(ctx, r)
	if err != nil {
		return nil, err
	}

	response := &validator.AuditResponse{
		Violations: []*validator.Violation{},
	}

	violations, err := convertToViolations(expressionVal)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	response.Violations = violations

	return response, nil
}
