// Package gcv provides a library and a RPC service for Google Config Validation.
package gcv

import "log"

// Asset contains GCP resource metadata and additional metadata set on a resource, such as Cloud IAM policy.
type Asset struct {
	// Underlying JSON object in the format exported by Cloud Assert Inventory.
	Object map[string]interface{}
}

// Type returns the asset type. Example: "google.cloud.sql.Instance" is the type of Cloud SQL instance.
// See https://cloud.google.com/resource-manager/docs/cloud-asset-inventory/overview#supported_resource_types for the list of types.
func (a *Asset) Type() string {
	log.Fatal("Not implemented")
	return ""
}

// Name returns the name of the GCP resource as defined by Cloud Asset Inventory.
// See https://cloud.google.com/resource-manager/docs/cloud-asset-inventory/resource-name-format for the format.
func (a *Asset) Name() string {
	log.Fatal("Not implemented")
	return ""
}

// AncestryPath returns the ancestral project/folder/org information in a path-like format.
// For example, a GCP project that is nested under a folder may have the following path:
// organization/9999/folders/8888/projects/7777
//
// This information is typically not available in the GCP resource name.
func (a *Asset) AncestryPath() string {
	log.Fatal("Not implemented")
	return ""
}

// Resource returns the GCP resource metadata in a generic string to interface map.
// The keys/values are determined by the resource type.
func (a *Asset) Resource() map[string]interface{} {
	log.Fatal("Not implemented")
	return nil
}

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
func (v *Validator) AddData(assets []Asset) error {
	log.Fatal("Not implemented")
	return nil
}

// Reset clears previously added data from the underlying query evaluation engine.
func (v *Validator) Reset() error {
	log.Fatal("Not implemented")
	return nil
}

// A Violation contains the relevant information to explain how a constraint is violated.
type Violation struct {
	// Constraint holds the name of the constraint that's violated.
	Constraint string
	// Resource is the GCP resource name. This is the same name in Asset.
	Resource string
	// Message contains the human readable error message.
	Message string
	// Metadata is optional. It contains the constraint-specific information that can potentially be used for remediation.
	// Example: In a firewall rule constraint violation, Metadata can contain the open port number.
	Metadata map[string]interface{}
}

// Audit checks the GCP resource metadata that has been added via AddData to determine if any of the constraint is violated.
func (v *Validator) Audit() ([]Violation, error) {
	log.Fatal("Not implemented")
	return nil, nil
}
