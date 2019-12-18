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
	"strings"

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
	cftypes "github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/pkg/errors"
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
	cfClient         *cfclient.Client
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

// NewValidatorFromConfig creates the validator from a config.
func NewValidatorFromConfig(stopChannel <-chan struct{}, config *configs.Configuration) (*Validator, error) {
	driver := local.New(local.Tracing(false))
	backend, err := cfclient.NewBackend(cfclient.Driver(driver))
	if err != nil {
		return nil, errors.Wrap(err, "unable to set up Constraint Framework backend")
	}
	client, err := backend.NewClient(cfclient.Targets(gcptarget.New()))
	if err != nil {
		return nil, errors.Wrap(err, "unable to set up Constraint Framework client")
	}

	ctx := context.Background()
	for _, template := range config.Templates {
		if _, err := client.AddTemplate(ctx, template); err != nil {
			return nil, errors.Wrapf(err, "failed to add template %v", template)
		}
	}

	for _, constraint := range config.Constraints {
		if _, err := client.AddConstraint(ctx, constraint); err != nil {
			return nil, errors.Wrapf(err, "failed to add constraint %s", constraint)
		}
	}

	ret := &Validator{
		work:     make(chan func(), flags.workerCount*2),
		cfClient: client,
	}

	go func() {
		<-stopChannel
		glog.Infof("validator stopchannel closed, closing work channel")
		close(ret.work)
	}()

	workerCount := flags.workerCount
	glog.Infof("starting %d workers", workerCount)
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
	glog.Infof("worker %d starting", idx)
	for f := range v.work {
		f()
	}
	glog.Infof("worker %d terminated", idx)
}

// AddData adds GCP resource metadata to be audited later.
func (v *Validator) AddData(request *validator.AddDataRequest) error {
	return errors.Errorf("Not supported")
}

type assetResult struct {
	violations []*validator.Violation
	err        error
}

func (v *Validator) handleReview(ctx context.Context, idx int, asset *validator.Asset, resultChan chan<- *assetResult) func() {
	return func() {
		resultChan <- func() *assetResult {
			if err := asset2.ValidateAsset(asset); err != nil {
				return &assetResult{err: errors.Wrapf(err, "index %d", idx)}
			}
			if asset.AncestryPath == "" && len(asset.Ancestors) != 0 {
				asset.AncestryPath = ancestryPath(asset.Ancestors)
			}

			assetInterface, err := asset2.ConvertResourceViaJSONToInterface(asset)
			if err != nil {
				return &assetResult{err: errors.Wrapf(err, "index %d", idx)}
			}

			responses, err := v.cfClient.Review(ctx, assetInterface)
			if err != nil {
				return &assetResult{err: errors.Wrapf(err, "index %d", idx)}
			}

			violations, err := v.convertResponses(responses)
			if err != nil {
				return &assetResult{err: errors.Wrapf(err, "failed to convert responses %v", responses)}
			}

			return &assetResult{violations: violations}
		}()
	}
}

// ancestryPath returns the ancestry path from a given ancestors list
func ancestryPath(ancestors []string) string {
	cnt := len(ancestors)
	revAncestors := make([]string, len(ancestors))
	for idx := 0; idx < cnt; idx++ {
		revAncestors[cnt-idx-1] = ancestors[idx]
	}
	return strings.Join(revAncestors, "/")
}

// fixAncestry will try to use the ancestors array to create the ancestorPath
// value if it is not present.
func (v *Validator) fixAncestry(input map[string]interface{}) error {
	if _, found := input[ancestryPathKey]; found {
		return nil
	}

	ancestorsIface, found := input[ancestorsKey]
	if !found {
		glog.Infof("asset missing ancestry information: %v", input)
		return nil
	}
	ancestorsIfaceSlice, ok := ancestorsIface.([]interface{})
	if !ok {
		return errors.Errorf("ancestors field not array type: %s", input)
	}
	if len(ancestorsIfaceSlice) == 0 {
		return nil
	}
	ancestors := make([]string, len(ancestorsIfaceSlice))
	for idx, v := range ancestorsIfaceSlice {
		val, ok := v.(string)
		if !ok {
			return errors.Errorf("ancestors field idx %d is not string %s, %s", idx, v, input)
		}
		ancestors[idx] = val
	}
	input[ancestryPathKey] = ancestryPath(ancestors)
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
	responses, err := v.cfClient.Review(ctx, asset)
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

// Reset clears previously added data from the underlying query evaluation engine.
func (v *Validator) Reset(ctx context.Context) error {
	return errors.Errorf("Reset not supported")
}

// Audit checks the GCP resource metadata that has been added via AddData to determine if any of the constraint is violated.
func (v *Validator) Audit(ctx context.Context) (*validator.AuditResponse, error) {
	return nil, errors.Errorf("Audit not supported")
}
