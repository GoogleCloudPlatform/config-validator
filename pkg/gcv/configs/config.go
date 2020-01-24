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

// configs helps with loading and parsing configuration files
package configs

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/forseti-security/config-validator/pkg/multierror"
	"github.com/golang/glog"
	cfapis "github.com/open-policy-agent/frameworks/constraint/pkg/apis"
	cfv1alpha1 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1alpha1"
	cftemplates "github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/regorewriter"
	"github.com/pkg/errors"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/kubectl/pkg/scheme"
)

func init() {
	utilruntime.Must(cfapis.AddToScheme(scheme.Scheme))
	utilruntime.Must(apiextensions.AddToScheme(scheme.Scheme))
	utilruntime.Must(apiextensionsv1beta1.AddToScheme(scheme.Scheme))
}

const (
	constraintGroup = "constraints.gatekeeper.sh"
	expectedTarget  = "validation.gcp.forsetisecurity.org"
	yamlPath        = expectedTarget + "/yamlpath"
)

var (
	// templateGK is the GroupKind for ConstraintTemplate types.
	TemplateGK = schema.GroupKind{Group: cfv1alpha1.SchemeGroupVersion.Group, Kind: "ConstraintTemplate"}
)

func arrayFilterSuffix(arr []string, suffix string) []string {
	var filteredList []string
	for _, s := range arr {
		if strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix)) {
			filteredList = append(filteredList, s)
		}
	}
	return filteredList
}

// ListYAMLFiles returns a list of YAML files under a dir. Errors will be grpc errors.
func ListYAMLFiles(dir string) ([]string, error) {
	return ListYAMLFilesD([]string{dir})
}

// ListYAMLFiles returns a list of YAML files under a dir. Errors will be grpc errors.
func ListYAMLFilesD(dirs []string) ([]string, error) {
	var files []string
	for _, dir := range dirs {
		configDir, err := newDir(dir)
		if err != nil {
			return nil, err
		}

		dirFiles, err := configDir.listFiles()
		if err != nil {
			return nil, err
		}
		glog.V(2).Infof("Found %d YAML files in dir %s", len(dirFiles), dir)
		files = append(files, dirFiles...)
	}
	return arrayFilterSuffix(files, ".yaml"), nil
}

//ListRegoFiles returns a list of rego files under a dir. Errors will be grpc errors.
func ListRegoFiles(dir string) ([]string, error) {
	configDir, err := newDir(dir)
	if err != nil {
		return nil, err
	}

	files, err := configDir.listFiles()
	if err != nil {
		return nil, err
	}
	glog.V(2).Infof("Found %d rego files in dir %s", len(files), dir)

	return arrayFilterSuffix(files, ".rego"), nil
}

// loadUnstructured loads .yaml files from the provided directories as k8s
// unstructured.Unstructured types.
func loadUnstructured(dirs []string) ([]*unstructured.Unstructured, error) {
	var err error

	files, err := ListYAMLFilesD(dirs)
	if err != nil {
		return nil, err
	}

	var yamlDocs []*unstructured.Unstructured
	for _, file := range files {
		glog.V(2).Infof("Loading yaml file: %s", file)
		configFile, err := newFile(file)
		if err != nil {
			return nil, err
		}

		contents, err := configFile.read()
		if err != nil {
			return nil, err
		}

		documents := strings.Split(string(contents), "\n---")
		for _, rawDoc := range documents {
			document := strings.TrimLeft(rawDoc, "\n ")
			if len(document) == 0 {
				continue
			}

			var u unstructured.Unstructured
			_, _, err := scheme.Codecs.UniversalDeserializer().Decode([]byte(document), nil, &u)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to decode %s", file)
			}

			annotations := u.GetAnnotations()
			if annotations == nil {
				annotations = map[string]string{}
			}
			annotations[yamlPath] = file
			u.SetAnnotations(annotations)
			yamlDocs = append(yamlDocs, &u)
		}
	}
	if len(yamlDocs) == 0 {
		return nil, fmt.Errorf("zero configurations found in the provided directories: %v", dirs)
	}
	return yamlDocs, nil
}

const regoAdapter = `
violation[{"msg": message, "details": metadata}] {
	deny[{"msg": message, "details": metadata}] with input as {"asset": input.review, "constraint": {"spec": {"parameters": input.parameters}}}
}
`

func injectRegoAdapter(rego string) string {
	return rego + "\n" + regoAdapter
}

// convertLegacyConstraintTemplate handles converting a legacy forseti v1alpha1 ConstraintTemplate
// to a constraint framework v1alpha1 ConstraintTemplate.
func convertLegacyConstraintTemplate(u *unstructured.Unstructured, regoLib []string) error {
	targetMap, found, err := unstructured.NestedMap(u.Object, "spec", "targets")
	if err != nil && !found {
		return nil
	}

	if u.GroupVersionKind().Version != "v1alpha1" {
		return errors.Errorf("only v1alpha1 constraint templates are eligible for legacy conversion")
	}

	// Make name match kind as appropriate
	ctKind, found, err := unstructured.NestedString(u.Object, "spec", "crd", "spec", "names", "kind")
	if err != nil {
		return errors.Wrapf(err, "invalid kind at spec.crd.spec.names.kind")
	}
	if !found {
		return errors.Errorf("No kind found at spec.crd.spec.names.kind")
	}

	if len(targetMap) != 1 {
		return errors.Errorf("got invalid number of targets %d", len(targetMap))
	}

	// Transcode target
	var targets []interface{}
	for name, targetIface := range targetMap {
		legacyTarget, ok := targetIface.(map[string]interface{})
		if !ok {
			return errors.Errorf("wrong type in legacy target")
		}

		target := map[string]interface{}{}
		regoIface, found := legacyTarget["rego"]
		if !found {
			return errors.Errorf("no rego specified in template")
		}
		rego, ok := regoIface.(string)
		if !ok {
			return errors.Errorf("failed to get rego from template")
		}

		rr, err := regorewriter.New(regorewriter.NewPackagePrefixer("lib"), []string{"data.validator"}, nil)
		if err != nil {
			return errors.Wrapf(err, "failed to create rego rewriter")
		}
		for idx, lib := range regoLib {
			if err := rr.AddLib(fmt.Sprintf("idx-%d.rego", idx), lib); err != nil {
				return errors.Wrapf(err, "failed to add lib %d", idx)
			}
		}
		if err := rr.AddEntryPoint("template-rego", injectRegoAdapter(rego)); err != nil {
			return errors.Wrapf(err, "failed to add source")
		}
		srcs, err := rr.Rewrite()
		if err != nil {
			return errors.Wrapf(err, "failed to rewrite")
		}

		if len(srcs.EntryPoints) != 1 {
			return errors.Errorf("invalid number of entrypoints")
		}

		newRego, err := srcs.EntryPoints[0].Content()
		if err != nil {
			return errors.Wrapf(err, "failed to convert rego to bytes")
		}
		var libs []interface{}
		for _, lib := range srcs.Libs {
			libBytes, err := lib.Content()
			if err != nil {
				return errors.Wrapf(err, "failed to convert lib to bytes")
			}
			libs = append(libs, string(libBytes))
		}

		target["rego"] = string(newRego)
		target["libs"] = libs
		target["target"] = name
		targets = append(targets, target)
	}

	if err := unstructured.SetNestedSlice(u.Object, targets, "spec", "targets"); err != nil {
		return errors.Wrapf(err, "failed to set transcoded target spec")
	}
	u.SetName(strings.ToLower(ctKind))
	return nil
}

var terminatingStarRegex = regexp.MustCompilePOSIX(`/\*$`)
var starRegex = regexp.MustCompilePOSIX(`/\*/`)

func fixLegacyMatcher(ancestry string) string {
	normalized := NormalizeAncestry(ancestry)
	return starRegex.ReplaceAllString(
		terminatingStarRegex.ReplaceAllString(normalized, "/**"),
		"/**/",
	)
}

func NormalizeAncestry(val string) string {
	for _, r := range []struct {
		old string
		new string
	}{
		{"organization/", "organizations/"},
		{"folder/", "folders/"},
		{"project/", "projects/"},
	} {
		val = strings.ReplaceAll(val, r.old, r.new)
	}
	return val
}

func convertLegacyCRM(obj map[string]interface{}, field ...string) error {
	strs, found, err := unstructured.NestedStringSlice(obj, field...)
	if err != nil {
		return errors.Wrapf(err, "invalid field type for %s", field)
	}
	if !found {
		return nil
	}
	for idx, val := range strs {
		strs[idx] = fixLegacyMatcher(val)
	}
	return unstructured.SetNestedStringSlice(obj, strs, field...)
}

func convertLegacyConstraint(u *unstructured.Unstructured) error {
	name := u.GetName()
	name = strings.ToLower(name)
	name = strings.Replace(name, "_", "-", -1)
	u.SetName(name)
	if err := convertLegacyCRM(u.Object, "spec", "match", "target"); err != nil {
		return err
	}
	if err := convertLegacyCRM(u.Object, "spec", "match", "exclude"); err != nil {
		return err
	}
	return nil
}

// Configuration represents the configuration files fed into FCV.
type Configuration struct {
	Templates   []*cftemplates.ConstraintTemplate
	Constraints []*unstructured.Unstructured
	regoLib     []string
}

func loadRegoFiles(dir string) ([]string, error) {
	var libs []string
	var content []byte
	files, err := ListRegoFiles(dir)

	if err != nil {
		return nil, errors.Wrapf(err, "failed to list rego files from %s", dir)
	}

	for _, filePath := range files {
		glog.V(2).Infof("Loading rego file: %s", filePath)

		configFile, err := newFile(filePath)
		if err != nil {
			return nil, err
		}

		content, err = configFile.read()
		if err != nil {
			return nil, err
		}

		if err != nil {
			return nil, errors.Wrapf(err, "unable to read file %s", filePath)
		}
		libs = append(libs, string(content))
	}
	sort.Strings(libs)
	return libs, nil
}

func (c *Configuration) loadUnstructured(u *unstructured.Unstructured) error {
	switch {
	case u.GroupVersionKind().GroupKind() == TemplateGK:
		switch u.GroupVersionKind().Version {
		case "v1alpha1":
			openAPIResult := configValidatorV1Alpha1SchemaValidator.Validate(u.Object)
			if openAPIResult.HasErrorsOrWarnings() {
				return errors.Wrapf(openAPIResult.AsError(), "v1alpha1 validation failure")
			}

			if err := convertLegacyConstraintTemplate(u, c.regoLib); err != nil {
				return errors.Wrapf(err, "failed to convert legacy forseti ConstraintTemplate "+
					"to ConstraintFramework format, this is likely due to an issue in the spec.crd.spec.validation field")
			}
		case "v1beta1":
			openAPIResult := configValidatorV1Beta1SchemaValidator.Validate(u.Object)
			if openAPIResult.HasErrorsOrWarnings() {
				return errors.Wrapf(openAPIResult.AsError(), "v1alpha1 validation failure")
			}
		default:
			return errors.Errorf("unrecognized ConstraintTemplate version %s", u.GroupVersionKind().Version)
		}

		groupVersioner := runtime.GroupVersioner(schema.GroupVersions(scheme.Scheme.PrioritizedVersionsAllGroups()))
		obj, err := scheme.Scheme.ConvertToVersion(u, groupVersioner)
		if err != nil {
			return errors.Wrapf(err, "failed to convert unstructured ConstraintTemplate to versioned")
		}

		var ct cftemplates.ConstraintTemplate
		if err := scheme.Scheme.Convert(obj, &ct, nil); err != nil {
			return errors.Wrapf(err, "failed to convert to versioned constraint template internal struct")
		}

		c.Templates = append(c.Templates, &ct)
	case u.GroupVersionKind().Group == constraintGroup:
		if err := convertLegacyConstraint(u); err != nil {
			return errors.Wrapf(err, "failed to convert constraint")
		}

		c.Constraints = append(c.Constraints, u)
	default:
		return errors.Errorf("unexpected data type %s", u.GroupVersionKind())
	}
	return nil
}

// NewConfiguration returns the configuration from the list of provided directories.
func NewConfiguration(dirs []string, libDir string) (*Configuration, error) {
	unstructuredObjects, err := loadUnstructured(dirs)
	if err != nil {
		return nil, err
	}

	regoLib, err := loadRegoFiles(libDir)
	if err != nil {
		return nil, err
	}

	var errs multierror.Errors
	configuration := &Configuration{regoLib: regoLib}
	for _, u := range unstructuredObjects {
		if err := configuration.loadUnstructured(u); err != nil {
			yamlPath := u.GetAnnotations()[yamlPath]
			name := u.GetName()
			errs.Add(errors.Wrapf(err, "failed to load resource %s %s", yamlPath, name))
		}
	}
	if !errs.Empty() {
		return nil, errs.ToError()
	}
	return configuration, nil
}
