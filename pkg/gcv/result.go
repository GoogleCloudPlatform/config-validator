// Copyright 2020 Google LLC
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

package gcv

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/GoogleCloudPlatform/config-validator/pkg/api/validator"
	"github.com/GoogleCloudPlatform/config-validator/pkg/gcv/configs"
	cftypes "github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	ConstraintKey = "constraint"
)

// Result is the result of reviewing an individual resource
type Result struct {
	// The name of the resource as given to Config Validator
	Name string
	// InputResource is the resource as given to Config Validator. This may be a
	// CAI Asset or a Terraform Resource Change.
	InputResource map[string]interface{}
	// ReviewResource is the resource sent to Constraint Framework for review.
	// This may be a CAI Asset, K8S resource, or Terraform Resource Change.
	ReviewResource map[string]interface{}
	// ConstraintViolations are the constraints that were not satisfied during review.
	ConstraintViolations []ConstraintViolation
}

// NewResult creates a Result from the provided CF Response.
func NewResult(
	target, name string,
	inputResource map[string]interface{},
	reviewResource map[string]interface{},
	responses *cftypes.Responses) (*Result, error) {
	cfResponse, found := responses.ByTarget[target]
	if !found {
		return nil, errors.Errorf("No response for target %s", target)
	}

	result := &Result{
		Name:                 name,
		InputResource:        inputResource,
		ReviewResource:       reviewResource,
		ConstraintViolations: make([]ConstraintViolation, len(cfResponse.Results)),
	}
	for idx, cfResult := range cfResponse.Results {
		for k := range cfResult.Metadata {
			if k == ConstraintKey {
				return nil, errors.Errorf("constraint template metadata contains reserved key %s", ConstraintKey)
			}
		}
		severity, found, err := unstructured.NestedString(cfResult.Constraint.Object, "spec", "severity")
		if err != nil || !found {
			severity = ""
		}
		result.ConstraintViolations[idx] = ConstraintViolation{
			Message:    cfResult.Msg,
			Metadata:   cfResult.Metadata,
			Constraint: cfResult.Constraint,
			Severity:   severity,
		}
	}
	return result, nil
}

// ConstraintViolations represents an unsatisfied constraint
type ConstraintViolation struct {
	// Message is a human readable message for the violation
	Message string
	// Metadata is the metadata returned by the constraint check
	Metadata map[string]interface{}
	// Constraint is the K8S resource of the constraint that triggered the violation
	Constraint *unstructured.Unstructured
	// Constraint Severity
	Severity string
}

// ToInsights returns the result represented as a slice of insights.
func (r *Result) ToInsights() []*Insight {
	if len(r.ConstraintViolations) == 0 {
		return nil
	}

	insights := make([]*Insight, len(r.ConstraintViolations))
	for idx, cv := range r.ConstraintViolations {
		i := &Insight{
			Description:     cv.Message,
			TargetResources: []string{r.Name},
			InsightSubtype:  cv.name(),
			Content: map[string]interface{}{
				"resource": r.InputResource,
				"metadata": cv.metadata(nil),
			},
			Category: "SECURITY",
		}
		insights[idx] = i
	}
	return insights
}

func (r *Result) ToViolations() ([]*validator.Violation, error) {
	auxMetadata := map[string]interface{}{}
	ancestryPath, found, err := unstructured.NestedString(r.InputResource, ancestryPathKey)
	if err != nil {
		return nil, errors.Wrapf(err, "error getting ancestry path from %v", r.InputResource)
	}
	if found {
		auxMetadata[ancestryPathKey] = ancestryPath
	}

	var violations []*validator.Violation
	for _, rv := range r.ConstraintViolations {
		violation, err := rv.toViolation(r.Name, auxMetadata)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to convert result")
		}
		violations = append(violations, violation)
	}
	return violations, nil
}

func (cv *ConstraintViolation) metadata(auxMetadata map[string]interface{}) map[string]interface{} {
	labels := cv.Constraint.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	annotations := cv.Constraint.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	params, found, err := unstructured.NestedMap(cv.Constraint.Object, "spec", "parameters")
	if err != nil {
		panic(fmt.Sprintf(
			"constraint has invalid schema (%#v), should have already been validated, "+
				" .spec.parameters got schema error on access: %s", cv.Constraint.Object, err))
	}
	if !found {
		params = map[string]interface{}{}
	}
	metadata := map[string]interface{}{
		ConstraintKey: map[string]interface{}{
			"labels":      labels,
			"annotations": annotations,
			"parameters":  params,
		},
	}
	for k, v := range auxMetadata {
		metadata[k] = v
	}
	for k, v := range cv.Metadata {
		metadata[k] = v
	}
	return metadata
}

// name returns the name for the constraint, this is given as "[Kind].[Name]" to uniquely identify which template and
// constraint the violation came from.
func (cv *ConstraintViolation) name() string {
	name := cv.Constraint.GetName()
	ans := cv.Constraint.GetAnnotations()
	if ans != nil {
		if originalName, ok := ans[configs.OriginalName]; ok {
			name = originalName
		}
	}
	return fmt.Sprintf("%s.%s", cv.Constraint.GetKind(), name)
}

// toViolation converts the constriant to a violation.
func (cv *ConstraintViolation) toViolation(name string, auxMetadata map[string]interface{}) (*validator.Violation, error) {
	metadataJson, err := json.Marshal(cv.metadata(auxMetadata))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal result metadata %v to json", cv.Metadata)
	}
	metadata := &structpb.Value{}
	if err := protojson.Unmarshal(metadataJson, metadata); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal json %s into structpb", string(metadataJson))
	}

	// Extract the object fields if they exists.
	var apiVersion string
	if constraintAPIVersion, ok := cv.Constraint.Object["apiVersion"]; ok {
		apiVersion = fmt.Sprintf("%s", constraintAPIVersion)
	}

	var kind string
	if constraintKind, ok := cv.Constraint.Object["kind"]; ok {
		kind = fmt.Sprintf("%s", constraintKind)
	}

	var pbMetadata *structpb.Value
	if constraintMetadata, ok := cv.Constraint.Object["metadata"]; ok {
		if pbMetadata, err = convertToProtoVal(constraintMetadata); err != nil {
			return nil, errors.Wrapf(err, "failed to convert constraint metadata into structpb.Value")
		}
	}

	var pbSpec *structpb.Value
	if constraintSpec, ok := cv.Constraint.Object["spec"]; ok {
		if pbSpec, err = convertToProtoVal(constraintSpec); err != nil {
			return nil, errors.Wrapf(err, "failed to convert constraint spec into structpb.Value")
		}
	}

	// Build the ConstraintConfig proto.
	constraintConfig := &validator.Constraint{
		ApiVersion: apiVersion,
		Kind:       kind,
		Metadata:   pbMetadata,
		Spec:       pbSpec,
	}

	return &validator.Violation{
		Constraint:       cv.name(),
		ConstraintConfig: constraintConfig,
		Resource:         name,
		Message:          cv.Message,
		Metadata:         metadata,
		Severity:         cv.Severity,
	}, nil
}

type convertFailed struct {
	err error
}

// convertToProtoVal converts an interface into a proto struct value.
func convertToProtoVal(from interface{}) (val *structpb.Value, err error) {
	defer func() {
		if x := recover(); x != nil {
			convFail, ok := x.(*convertFailed)
			if !ok {
				panic(x)
			}
			val = nil
			err = errors.Errorf("failed to convert proto val: %s", convFail.err)
		}
	}()
	val = convertToProtoValInternal(from)
	return
}

func convertToProtoValInternal(from interface{}) *structpb.Value {
	if from == nil {
		return nil
	}
	switch val := from.(type) {
	case map[string]interface{}:
		fields := map[string]*structpb.Value{}
		for k, v := range val {
			fields[k] = convertToProtoValInternal(v)
		}
		return &structpb.Value{
			Kind: &structpb.Value_StructValue{
				StructValue: &structpb.Struct{
					Fields: fields,
				},
			}}

	case []interface{}:
		vals := make([]*structpb.Value, len(val))
		for idx, v := range val {
			vals[idx] = convertToProtoValInternal(v)
		}
		return &structpb.Value{
			Kind: &structpb.Value_ListValue{
				ListValue: &structpb.ListValue{Values: vals},
			},
		}

	case string:
		return &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: val}}
	case int:
		return &structpb.Value{Kind: &structpb.Value_NumberValue{NumberValue: float64(val)}}
	case int64:
		return &structpb.Value{Kind: &structpb.Value_NumberValue{NumberValue: float64(val)}}
	case float64:
		return &structpb.Value{Kind: &structpb.Value_NumberValue{NumberValue: val}}
	case float32:
		return &structpb.Value{Kind: &structpb.Value_NumberValue{NumberValue: float64(val)}}
	case bool:
		return &structpb.Value{Kind: &structpb.Value_BoolValue{BoolValue: val}}

	default:
		panic(&convertFailed{errors.Errorf("Unhandled type %v (%s)", from, reflect.TypeOf(from).String())})
	}
}
