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

// Package gcv provides a library and a RPC service for Google Config Validation.
package gcv

import (
	"bytes"
	"github.com/golang/glog"
	"github.com/golang/protobuf/jsonpb"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io/ioutil"
	"partner-code.googlesource.com/gcv/gcv/pkg/api/validator"
	"partner-code.googlesource.com/gcv/gcv/pkg/gcv/cf"
	"partner-code.googlesource.com/gcv/gcv/pkg/gcv/configs"
)

// Validator checks GCP resource metadata for constraint violation.
//
// Expected usage pattern:
//   - call NewValidator to create a new Validator
//   - call AddData one or more times to add the GCP resource metadata to check
//   - call Audit to validate the GCP resource metadata that has been added so far
//   - call Reset to delete existing data
//   - call AddData to add a new set of GCP resource metadata to check
//   - call Reset to delete existing data
//
// Any data added in AddData stays in the underlying rule evaluation engine's memory.
// To avoid out of memory errors, callers can invoke Reset to delete existing data.
type Validator struct {
	// policyPath points to a directory where the constraints and constraint templates are stored as yaml files.
	policyPath    string
	// policy dependencies directory points to rego files that provide supporting code for templates.
	// These rego dependencies should be packaged with the GCV deployment.
	policyLibraryDir    string
	constraintFramework *cf.ConstraintFramework
}

// Option is a function for configuring Validator.
// See https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis for background.
type Option func(*Validator) error

// PolicyPath returns an Option that sets the root directory of constraints and constraint templates.
func PolicyPath(p string) Option {
	return func(v *Validator) error {
		v.policyPath = p
		return nil
	}
}

func PolicyLibraryDir(dir string) Option {
	return func(v *Validator) error {
		v.policyLibraryDir = dir
		return nil
	}
}

func loadRegoFiles(dir string) (map[string]string, error) {
	loadedFiles := make(map[string]string)
	files, err := configs.ListRegoFiles(dir)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument,err.Error())
	}
	for _, filePath := range files {
		if _,exists := loadedFiles[filePath]; exists {
			// This shouldn't happen
			return nil, status.Errorf(codes.Internal,"Unexpected file collision with file %s", filePath)
		}
		fileBytes, err := ioutil.ReadFile(filePath)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument,errors.Wrapf(err,"unable to read file %s", filePath).Error())
		}
		loadedFiles[filePath] = string(fileBytes)
	}
	return loadedFiles, nil
}

func loadYAMLFiles(dir string) ([]*configs.ConstraintTemplate, []*configs.Constraint, error) {
	var templates []*configs.ConstraintTemplate
	var constraints []*configs.Constraint
	files, err := configs.ListYAMLFiles(dir)
	if err != nil {
		return nil,nil,err
	}
	for _,filePath := range files {
		fileContents, err := ioutil.ReadFile(filePath)
		if err != nil {
			return nil, nil, status.Error(codes.InvalidArgument,errors.Wrapf(err,"unable to read file %s", filePath).Error())
		}
		categorizedData, err := configs.CategorizeYAMLFile(fileContents, filePath)
		if err != nil {
			glog.Infof("Unable to convert file %s, with error %v, assuming this file should be skipped and continuing", filePath, err)
			continue
		}
		switch data := categorizedData.(type) {
		case *configs.ConstraintTemplate:
			templates = append(templates, data)
		case *configs.Constraint:
			constraints = append(constraints, data)
		default:
			// Unexpected: CategorizeYAMLFile shouldn't return any types
			return nil, nil, status.Errorf(codes.Internal, "CategorizeYAMLFile returned unexpected data type when converting file %s", filePath)
		}
	}
	return templates, constraints, nil
}

// NewValidator returns a new Validator.
// By default it will initialize the underlying query evaluation engine by loading supporting library, constraints, and constraint templates.
// We may want to make this initialization behavior configurable in the future.
func NewValidator(options ...Option) (*Validator, error) {
	ret := &Validator{}
	for _, option := range options {
		if err := option(ret); err != nil {
			return nil, err
		}
	}
	if ret.policyPath == "" {
		return nil, status.Errorf(codes.InvalidArgument,"No policy path set, provide an option to set the policy path gcv.PolicyPath")
	}
	if ret.policyLibraryDir == "" {
		return nil, status.Errorf(codes.InvalidArgument,"No policy library set")
	}

	regoLib, err := loadRegoFiles(ret.policyLibraryDir)
	if err != nil {
		return nil, err
	}

	ret.constraintFramework, err = cf.New(regoLib)
	if err != nil {
		return nil, err
	}
	templates, constraints, err := loadYAMLFiles(ret.policyPath)
	if err != nil {
		return nil, err
	}
	for _,template := range templates {
		if err := ret.constraintFramework.AddTemplate(template); err != nil {
			return nil, err
		}
	}
	for _,constraint := range constraints {
		if err := ret.constraintFramework.AddConstraint(constraint); err != nil {
			return nil, err
		}
	}

	return ret, nil
}


// AddData adds GCP resource metadata to be audited later.
func (v *Validator) AddData(request *validator.AddDataRequest) error {
	marshaler := &jsonpb.Marshaler{}
	for _,asset := range request.Assets {
		buf := new(bytes.Buffer)
		if err := marshaler.Marshal(buf, asset); err != nil {
			return status.Error(codes.Internal, errors.Wrap(err, "marshalling to json").Error())
		}
		// TODO(morgantep): verify this is how data is expected to be provided
		//  Assumption: data will be provided under different paths, alternative would be to provide all the data under a single var with a repeated field.
		// resource names are unique: https://cloud.google.com/apis/design/resource_names
		// More info on CAI's resource name format: https://cloud.google.com/resource-manager/docs/cloud-asset-inventory/resource-name-format
		v.constraintFramework.AddData(asset.Name, buf.String())
	}

	return nil
}

// Reset clears previously added data from the underlying query evaluation engine.
func (v *Validator) Reset() error {
	v.constraintFramework.Reset()
	return nil
}

// Audit checks the GCP resource metadata that has been added via AddData to determine if any of the constraint is violated.
func (v *Validator) Audit() (*validator.AuditResponse, error) {
	response,err := v.constraintFramework.Audit()
	return response, err

}
