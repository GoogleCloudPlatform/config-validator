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
	"partner-code.googlesource.com/gcv/gcv/pkg/api/validator"
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
	// policyPath points to a directory where the constraints and constraint templates are stored.
	policyPath string
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

// NewValidator returns a new Validator.
// By default it will initialize the underlying query evaluation engine by loading supporting library, constraints, and constraint templates.
// We may want to make this initialization behavior configurable in the future.
func NewValidator(options ...Option) (*Validator, error) {
	v := Validator{}
	for _, option := range options {
		if err := option(&v); err != nil {
			return nil, err
		}
	}
	return &v, nil
}

// AddData adds GCP resource metadata to be audited later.
func (v *Validator) AddData(*validator.AddDataRequest) error {
	return nil
}

// Reset clears previously added data from the underlying query evaluation engine.
func (v *Validator) Reset() error {
	return nil
}

// Audit checks the GCP resource metadata that has been added via AddData to determine if any of the constraint is violated.
func (v *Validator) Audit() (*validator.AuditResponse, error) {
	return &validator.AuditResponse{
		Violations: []*validator.Violation{
			{
				Constraint: "StubContraint",
				Resource:   "//compute.googleapis.com/projects/my-project/zones/my-zone/disks/my-disk",
				Message:    "Stub Message",
			},
		},
	}, nil
}
