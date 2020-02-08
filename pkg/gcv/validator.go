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

// Package gcv provides a library and a RPC service for Forseti Config Validator.
package gcv

import (
	"context"
	"encoding/json"
	"flag"
	"runtime"

	"github.com/forseti-security/config-validator/pkg/api/validator"
	asset2 "github.com/forseti-security/config-validator/pkg/asset"
	"github.com/forseti-security/config-validator/pkg/gcptarget"
	"github.com/forseti-security/config-validator/pkg/gcv/configs"
	"github.com/forseti-security/config-validator/pkg/multierror"
	"github.com/golang/glog"
	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"
	cfclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	cftemplates "github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	cftypes "github.com/open-policy-agent/frameworks/constraint/pkg/types"
	k8starget "github.com/open-policy-agent/gatekeeper/pkg/target"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	logRequestsVerboseLevel = 2
	// The JSON object key for ancestry path
	ancestryPathKey = "ancestry_path"
	// The JSON object key for ancestors list
	ancestorsKey = "ancestors"
)

var flags struct {
	workerCount int
}

func init() {
	flag.IntVar(
		&flags.workerCount,
		"workerCount",
		runtime.NumCPU(),
		"Number of workers that Validator will spawn to handle validate calls, this defaults to core count on the host")
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
	// policyPaths points to a list of directories where the constraints and
	// constraint templates are stored as yaml files.
	policyPaths []string
	// policy dependencies directory points to rego files that provide supporting code for templates.
	// These rego dependencies should be packaged with the GCV deployment.
	// Right now expected to be set to point to "//policies/validator/lib" folder
	policyLibraryDir string
	work             chan func()
	gcpCFClient      *cfclient.Client
	k8sCFClient      *cfclient.Client
}

// NewValidatorConfig returns a new ValidatorConfig.
// By default it will initialize the underlying query evaluation engine by loading supporting library, constraints, and constraint templates.
// We may want to make this initialization behavior configurable in the future.
func NewValidatorConfig(policyPaths []string, policyLibraryPath string) (*configs.Configuration, error) {
	if len(policyPaths) == 0 {
		return nil, errors.Errorf("No policy path set, provide an option to set the policy path gcv.PolicyPath")
	}
	if policyLibraryPath == "" {
		return nil, errors.Errorf("No policy library set")
	}
	glog.V(logRequestsVerboseLevel).Infof("loading policy dir: %v lib dir: %s", policyPaths, policyLibraryPath)
	return configs.NewConfiguration(policyPaths, policyLibraryPath)
}

func newCFClient(
	targetHandler cfclient.TargetHandler,
	templates []*cftemplates.ConstraintTemplate,
	constraints []*unstructured.Unstructured) (
	*cfclient.Client, error) {
	driver := local.New(local.Tracing(false))
	backend, err := cfclient.NewBackend(cfclient.Driver(driver))
	if err != nil {
		return nil, errors.Wrap(err, "unable to set up Constraint Framework backend")
	}
	cfClient, err := backend.NewClient(cfclient.Targets(targetHandler))
	if err != nil {
		return nil, errors.Wrap(err, "unable to set up Constraint Framework client")
	}

	ctx := context.Background()
	var errs multierror.Errors
	for _, template := range templates {
		if _, err := cfClient.AddTemplate(ctx, template); err != nil {
			errs.Add(errors.Wrapf(err, "failed to add template %v", template))
		}
	}
	if !errs.Empty() {
		return nil, errs.ToError()
	}

	for _, constraint := range constraints {
		if _, err := cfClient.AddConstraint(ctx, constraint); err != nil {
			errs.Add(errors.Wrapf(err, "failed to add constraint %s", constraint))
		}
	}
	if !errs.Empty() {
		return nil, errs.ToError()
	}
	return cfClient, nil
}

// NewValidatorFromConfig creates the validator from a config.
func NewValidatorFromConfig(stopChannel <-chan struct{}, config *configs.Configuration) (*Validator, error) {
	gcpCFClient, err := newCFClient(gcptarget.New(), config.GCPTemplates, config.GCPConstraints)
	if err != nil {
		return nil, errors.Wrap(err, "unable to set up GCP Constraint Framework client")
	}

	k8sCFClient, err := newCFClient(&k8starget.K8sValidationTarget{}, config.K8STemplates, config.K8SConstraints)
	if err != nil {
		return nil, errors.Wrap(err, "unable to set up K8S Constraint Framework client")
	}

	ret := &Validator{
		work:        make(chan func(), flags.workerCount*2),
		gcpCFClient: gcpCFClient,
		k8sCFClient: k8sCFClient,
	}

	go func() {
		<-stopChannel
		glog.Infof("validator shutdown requested via stopChannel close")
		close(ret.work)
	}()

	workerCount := flags.workerCount
	glog.Infof("validator starting %d workers", workerCount)
	for i := 0; i < workerCount; i++ {
		go ret.reviewWorker(i)
	}

	return ret, nil
}

// NewValidator returns a new Validator.
// By default it will initialize the underlying query evaluation engine by loading supporting library, constraints, and constraint templates.
// We may want to make this initialization behavior configurable in the future.
func NewValidator(stopChannel <-chan struct{}, policyPaths []string, policyLibraryPath string) (*Validator, error) {
	config, err := NewValidatorConfig(policyPaths, policyLibraryPath)
	if err != nil {
		return nil, err
	}
	return NewValidatorFromConfig(stopChannel, config)
}

func (v *Validator) reviewWorker(idx int) {
	glog.V(1).Infof("worker %d starting", idx)
	for f := range v.work {
		f()
	}
	glog.V(1).Infof("worker %d terminated", idx)
}

// AddData adds GCP resource metadata to be audited later.
func (v *Validator) AddData(request *validator.AddDataRequest) error {
	return errors.Errorf("Not supported")
}

type assetResult struct {
	violations []*validator.Violation
	err        error
}

// ReviewAsset reviews a single asset.
func (v *Validator) ReviewAsset(ctx context.Context, asset *validator.Asset) ([]*validator.Violation, error) {
	if err := asset2.ValidateAsset(asset); err != nil {
		return nil, err
	}

	if err := asset2.SanitizeAncestryPath(asset); err != nil {
		return nil, err
	}

	assetInterface, err := asset2.ConvertResourceViaJSONToInterface(asset)
	if err != nil {
		return nil, err
	}

	assetMapInterface := assetInterface.(map[string]interface{})
	return v.ReviewUnmarshalledJSON(ctx, assetMapInterface)
}

func (v *Validator) handleReview(ctx context.Context, idx int, asset *validator.Asset, resultChan chan<- *assetResult) func() {
	return func() {
		resultChan <- func() *assetResult {
			violations, err := v.ReviewAsset(ctx, asset)
			if err != nil {
				return &assetResult{err: errors.Wrapf(err, "index %d", idx)}
			}
			return &assetResult{violations: violations}
		}()
	}
}

// fixAncestry will try to use the ancestors array to create the ancestorPath
// value if it is not present.
func (v *Validator) fixAncestry(input map[string]interface{}) error {
	ancestry, found, err := unstructured.NestedString(input, ancestryPathKey)
	if found && err != nil {
		input[ancestryPathKey] = configs.NormalizeAncestry(ancestry)
		return nil
	}

	ancestors, found, err := unstructured.NestedStringSlice(input, ancestorsKey)
	if !found {
		glog.Infof("asset missing ancestry information: %v", input)
		return nil
	}
	if err != nil {
		return errors.Wrapf(err, "failed to access ancestors list")
	}
	if len(ancestors) == 0 {
		return nil
	}
	input[ancestryPathKey] = asset2.AncestryPath(ancestors)
	return nil
}

// ReviewJSON reviews the content of a JSON string
func (v *Validator) ReviewJSON(ctx context.Context, data string) ([]*validator.Violation, error) {
	asset := map[string]interface{}{}
	if err := json.Unmarshal([]byte(data), &asset); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal json")
	}
	return v.ReviewUnmarshalledJSON(ctx, asset)
}

func (v *Validator) convertResponses(responses *cftypes.Responses) ([]*validator.Violation, error) {
	response, found := responses.ByTarget[gcptarget.Name]
	if !found {
		return nil, errors.Errorf("No response for target %s", gcptarget.Name)
	}
	var violations []*validator.Violation
	for _, result := range response.Results {
		violation, err := v.convertResult(result)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to convert result")
		}
		violations = append(violations, violation)
	}
	return violations, nil
}

func (v *Validator) convertResult(result *cftypes.Result) (*validator.Violation, error) {
	metadataJson, err := json.Marshal(result.Metadata)
	if err != nil {
		return nil, errors.Wrapf(
			err, "failed to marshal result metadata %v to json", result.Metadata)
	}
	metadata := &structpb.Value{}
	if err := jsonpb.UnmarshalString(string(metadataJson), metadata); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal json %s into structpb", string(metadataJson))
	}
	res, ok := result.Resource.(map[string]interface{})
	if !ok {
		return nil, errors.Errorf("failed to cast resource to map[string]interface{}")
	}
	resNameIface, found := res["name"]
	if !found {
		return nil, errors.Errorf("result missing name field")
	}
	resName, ok := resNameIface.(string)
	if !ok {
		return nil, errors.Errorf("")
	}
	return &validator.Violation{
		Constraint: result.Constraint.GetName(),
		Resource:   resName,
		Message:    result.Msg,
		Metadata:   metadata,
	}, nil
}

// ReviewJSON evaluates a single asset without any threading in the background.
func (v *Validator) ReviewUnmarshalledJSON(ctx context.Context, asset map[string]interface{}) ([]*validator.Violation, error) {
	if err := v.fixAncestry(asset); err != nil {
		return nil, err
	}
	responses, err := v.gcpCFClient.Review(ctx, asset)
	if err != nil {
		return nil, errors.Wrapf(err, "Constraint Framework review call failed")
	}
	return v.convertResponses(responses)
}

// Review evaluates each asset in the review request in parallel and returns any
// violations found.
func (v *Validator) Review(ctx context.Context, request *validator.ReviewRequest) (*validator.ReviewResponse, error) {
	assetCount := len(request.Assets)
	resultChan := make(chan *assetResult, flags.workerCount*2)
	defer close(resultChan)

	go func() {
		for idx, asset := range request.Assets {
			v.work <- v.handleReview(ctx, idx, asset, resultChan)
		}
	}()

	response := &validator.ReviewResponse{}
	var errs multierror.Errors
	for i := 0; i < assetCount; i++ {
		result := <-resultChan
		if result.err != nil {
			errs.Add(result.err)
			continue
		}
		response.Violations = append(response.Violations, result.violations...)
	}

	if !errs.Empty() {
		return response, errs.ToError()
	}
	return response, nil
}
