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
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/smallfish/simpleyaml"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"partner-code.googlesource.com/gcv/gcv/pkg/api/validator"
	"partner-code.googlesource.com/gcv/gcv/pkg/gcv/configs"
)

// Constraint model framework organizes constraints/templates/data and handles evaluation.
type ConstraintFramework struct {
	userInputData map[string]interface{}
	// map[userDefined]regoCode
	dependencyCode map[string]string
	// map[kind]template
	templates map[string]*configs.ConstraintTemplate
	// map[kind]map[metadataname]constraint
	constraints map[string]map[string]*configs.Constraint
}

const (
	constraintTemplatesPackagePrefix    = "data.templates.gcp."
	constraintDependenciesPackagePrefix = "data.constraint_dep."
	inputDataPrefix                     = "data.inventory"
	constraintPathPrefix                = "data.config"
	regoLibraryRule                     = "data.validator.gcp.lib.audit"
)

func prefixMaxKeys(prefix string, src map[string]string) map[string]string {
	ret := make(map[string]string)
	for key, val := range src {
		ret[prefix+key] = val
	}
	return ret
}

// New creates a new ConstraintFramework
// args:
//   dependencyCode: map[debugString]regoCode: The debugString key will be referenced in compiler errors. It should help identify the source of the rego code.
func New(dependencyCode map[string]string) (*ConstraintFramework, error) {
	cf := ConstraintFramework{}
	cf.userInputData = make(map[string]interface{})
	cf.templates = make(map[string]*configs.ConstraintTemplate)
	cf.constraints = make(map[string]map[string]*configs.Constraint)
	_, compileErrors := ast.CompileModules(dependencyCode)
	if compileErrors != nil {
		return nil, status.Error(codes.InvalidArgument, compileErrors.Error())
	}
	// Adding this prefix will ensure there are no collisions with templates
	cf.dependencyCode = prefixMaxKeys(constraintDependenciesPackagePrefix, dependencyCode)
	return &cf, nil
}

// AddData adds GCP resource metadata to be audited later.
func (cf *ConstraintFramework) AddData(path string, objJSON interface{}) {
	if _, exists := cf.userInputData[path]; exists {
		glog.Infof("Existing asset at %s exists, overwriting", path)
	}
	cf.userInputData[path] = objJSON
}

// getTemplatePkgPath constructs a package prefix based off the generated type.
func getTemplatePkgPath(t *configs.ConstraintTemplate) string {
	return fmt.Sprintf("%s.%s", constraintTemplatesPackagePrefix, t.GeneratedKind)
}

// validateTemplate verifies template compiles
func (cf *ConstraintFramework) validateTemplate(t *configs.ConstraintTemplate) error {
	// validate rego code can be compiled
	_, err := staticCompile(cf.dependencyCode, map[string]*configs.ConstraintTemplate{
		getTemplatePkgPath(t): t,
	})
	return err
}

// AddTemplate tracks an additional constraint template. This template is only used if a constraint is provided.
func (cf *ConstraintFramework) AddTemplate(template *configs.ConstraintTemplate) error {
	if _, exists := cf.templates[template.GeneratedKind]; exists {
		return status.Errorf(codes.AlreadyExists, "Conflicting constraint templates with kind %s from file %s", template.GeneratedKind, template.Confg.FilePath)
	}
	if err := cf.validateTemplate(template); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	cf.templates[template.GeneratedKind] = template
	return nil
}

// validateConstraint validates template kind exists
// TODO(corb): will also validate constraint data confirms to template validation
func (cf *ConstraintFramework) validateConstraint(c *configs.Constraint) error {
	if _, exists := cf.templates[c.Confg.Kind]; !exists {
		return fmt.Errorf("no template found for kind %s, constraint's template needs to be loaded before constraint. ", c.Confg.Kind)
	}
	// TODO(corb): validate constraints data with template validation spec
	return nil
}

// AddConstraint adds a new constraint that will be used to validate data during Audit.
// This will validate that the constraint dependencies are already loaded and that the constraint data is valid.
func (cf *ConstraintFramework) AddConstraint(c *configs.Constraint) error {
	if _, ok := cf.constraints[c.Confg.Kind]; !ok {
		cf.constraints[c.Confg.Kind] = make(map[string]*configs.Constraint)
	}
	if _, exists := cf.constraints[c.Confg.Kind][c.Confg.MetadataName]; exists {
		return status.Errorf(codes.AlreadyExists, "Conflicting constraint metadata names with name %s from file %s", c.Confg.MetadataName, c.Confg.FilePath)
	}
	if err := cf.validateConstraint(c); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	cf.constraints[c.Confg.Kind][c.Confg.MetadataName] = c
	return nil
}

func staticCompile(dependencyCode map[string]string, templates map[string]*configs.ConstraintTemplate) (*ast.Compiler, error) {
	regoCode := make(map[string]string)

	for key, depRego := range dependencyCode {
		regoCode[key] = depRego
	}
	for _, template := range templates {
		key := getTemplatePkgPath(template)
		if _, exists := regoCode[key]; exists {
			return nil, fmt.Errorf("template overrides library package @ key %s", key)
		}
		regoCode[key] = template.Rego
	}
	return ast.CompileModules(regoCode)
}

func (cf *ConstraintFramework) compile() (*ast.Compiler, error) {
	return staticCompile(cf.dependencyCode, cf.templates)
}

// Reset the user provided data, preserving the constraint and template information.
func (cf *ConstraintFramework) Reset() {
	// Clear input data
	// This is provided as a param in audit
	cf.userInputData = make(map[string]interface{})
}

// constraintAsInputData prepares the constraint data for providing to rego. Rego input values support yaml, so the raw constraint data can be passed directly into rego.
// Passing the raw file data ensures we haven't lost any information when parsing.
// Input: map[kind][metadataname]constraint
// Returns: map[kind][]rawConstraintYAML
func constraintAsInputData(constraintMap map[string]map[string]*configs.Constraint) map[string][]string {
	// mimic the same type as the input, but have a string to store the raw constraint data
	flattened := make(map[string][]string)

	for kind, constraints := range constraintMap {
		for _, constraint := range constraints {
			flattened[kind] = append(flattened[kind], constraint.Confg.RawFile)
		}
	}

	return flattened
}

// Audit checks the GCP resource metadata that has been added via AddData to determine if any of the constraint is violated.
func (cf *ConstraintFramework) Audit(ctx context.Context) (*validator.AuditResponse, error) {
	compiler, err := cf.compile()
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	r := rego.New(
		rego.Query(regoLibraryRule),
		rego.Compiler(compiler),
		// TODO(morgantep): please PTAL to confirm this will integrate with rego expecations
		rego.Input(map[string]interface{}{
			inputDataPrefix:      cf.userInputData,
			constraintPathPrefix: constraintAsInputData(cf.constraints),
		}))

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, err
	}

	response := &validator.AuditResponse{
		Violations: []*validator.Violation{},
	}

	for _, result := range rs {
		for _, expression := range result.Expressions {
			violation, err := convertToViolation(expression)
			if err != nil {
				return nil, status.Error(codes.Internal, err.Error())
			}
			response.Violations = append(response.Violations, violation)
		}
	}

	return response, nil
}

func convertToViolation(expression *rego.ExpressionValue) (*validator.Violation, error) {
	// Convert into a YAML object to allow querying the structure
	asYaml, err := convertToYAML(expression.Value)
	if err != nil {
		return nil, err
	}
	constraint, err := asYaml.GetIndex(0).Get("constraint").String()
	if err != nil {
		return nil, err
	}
	asset , err:= asYaml.GetIndex(0).Get("asset").String()
	if err != nil {
		return nil, err
	}
	violation , err:= asYaml.GetIndex(0).Get("violation").String()
	if err != nil {
		return nil, err
	}
	return &validator.Violation{
		Constraint: constraint,
		Resource:   asset,
		Message:    violation,
		//Metadata: // TODO(corb): check and populate this field
	}, nil
}

func convertToYAML(obj interface{}) (*simpleyaml.Yaml, error) {
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return simpleyaml.NewYaml(jsonBytes)
}