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
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/golang/glog"

	"github.com/GoogleCloudPlatform/config-validator/pkg/multierror"
	cfapis "github.com/open-policy-agent/frameworks/constraint/pkg/apis"
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

// TODO: Using constant from gcptarget/tftarget packages causes circular reference.  Fix circular reference and use <package>.Name
const (
	K8STargetName = "admission.k8s.gatekeeper.sh"
	GCPTargetName = "validation.gcp.forsetisecurity.org"
	TFTargetName  = "validation.resourcechange.terraform.cloud.google.com"
)

const (
	constraintGroup = "constraints.gatekeeper.sh"
	templateGroup   = "templates.gatekeeper.sh"
	yamlPath        = GCPTargetName + "/yamlpath"
	OriginalName    = GCPTargetName + "/originalName"
)

const (
	gcpConstraint = "gcp"
	k8sConstraint = "k8s"
	tfConstraint  = "terraform"
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

func setAnnotation(u *unstructured.Unstructured, key, value string) {
	annotations := u.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[key] = value
	u.SetAnnotations(annotations)
}

// PolicyFile represents a .yaml file with its path and contents,
// which may or may not have been loaded from the file system.
type PolicyFile struct {
	Path    string
	Content []byte
}

// LoadUnstructured loads .yaml files from the provided directories as k8s
// unstructured.Unstructured types.
func LoadUnstructured(dirs []string) ([]*unstructured.Unstructured, error) {
	var files []*PolicyFile
	for _, dir := range dirs {
		dirPath, err := NewPath(dir)
		if err != nil {
			return nil, err
		}
		dirFiles, err := dirPath.ReadAll(context.Background(), SuffixPredicate(".yaml"))
		if err != nil {
			return nil, err
		}
		for _, dirFile := range dirFiles {
			files = append(files, &PolicyFile{
				Path:    dirFile.Path,
				Content: dirFile.Content,
			})
		}
	}

	yamlDocs, err := LoadUnstructuredFromContents(files)
	if err != nil {
		return nil, err
	}
	if len(yamlDocs) == 0 {
		return nil, fmt.Errorf("zero configurations found in the provided directories: %v", dirs)
	}
	return yamlDocs, nil
}

// LoadUnstructuredFromContents loads provided file contents as k8s unstructured.Unstructured types.
func LoadUnstructuredFromContents(files []*PolicyFile) ([]*unstructured.Unstructured, error) {
	var yamlDocs []*unstructured.Unstructured
	for _, file := range files {
		documents := strings.Split(string(file.Content), "\n---")
		for _, rawDoc := range documents {
			document := strings.TrimLeft(rawDoc, "\n ")
			if len(document) == 0 {
				continue
			}

			var u unstructured.Unstructured
			_, _, err := scheme.Codecs.UniversalDeserializer().Decode([]byte(document), nil, &u)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to decode %s", file.Path)
			}

			setAnnotation(&u, yamlPath, file.Path)
			yamlDocs = append(yamlDocs, &u)
		}
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
// Legacy constraint templates use `deny` as an entrypoint and the expected inputs are:
// - `input.asset`: the CAI asset being reviewed (new templates use `input.review`)
// - `input.constraint.spec.parameters`: the parameters from the constraint template (new templates use `input.parameters`)
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
	originalName := u.GetName()
	u.SetName(strings.ToLower(ctKind))
	setAnnotation(u, OriginalName, originalName)
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

func convertLegacyResourceName(u *unstructured.Unstructured) {
	originalName := u.GetName()
	compatibleName := strings.ReplaceAll(strings.ToLower(originalName), "_", "-")
	if originalName == compatibleName {
		return
	}
	u.SetName(compatibleName)
	setAnnotation(u, OriginalName, originalName)
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
	convertLegacyResourceName(u)
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
	GCPTemplates   []*cftemplates.ConstraintTemplate // Constraint Templates for GCP
	GCPConstraints []*unstructured.Unstructured      // Constraints for GCP
	K8STemplates   []*cftemplates.ConstraintTemplate // Constraint Templates for GKE
	K8SConstraints []*unstructured.Unstructured      // Constraints for GKE
	TFTemplates    []*cftemplates.ConstraintTemplate // Constraint Templates for TF
	TFConstraints  []*unstructured.Unstructured      // Constraints for TF

	// regoLib contains the set of rego libraries, it is only used during construction of Configuration
	regoLib []string
	// allConstraints contains all input constraints, it is only used during construction of Configuration
	allConstraints []*unstructured.Unstructured
	// templateNames is a set of the names of all templates for checking exclusivity.
	templateNames map[string]*cftemplates.ConstraintTemplate
	// templateNames is a set of the kinds of all templates for checking exclusivity.
	templateKinds map[string]*cftemplates.ConstraintTemplate
}

func newConfiguration() *Configuration {
	return &Configuration{
		templateNames: map[string]*cftemplates.ConstraintTemplate{},
		templateKinds: map[string]*cftemplates.ConstraintTemplate{},
	}
}

// LoadRegoFiles load rego policy library files from the given directory.
func LoadRegoFiles(dir string) ([]string, error) {
	dirPath, err := NewPath(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to handle path for %s", dir)
	}

	files, err := dirPath.ReadAll(context.Background(), SuffixPredicate(".rego"))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read files from %s", dir)
	}

	var libs []string
	for _, f := range files {
		libs = append(libs, string(f.Content))
	}
	sort.Strings(libs)
	return libs, nil
}

func (c *Configuration) loadUnstructured(u *unstructured.Unstructured) error {
	switch u.GroupVersionKind().Group {
	case constraintGroup:
		if u.GroupVersionKind().Version == "v1alpha1" {
			glog.Warning(
				"v1alpha1 constraints are deprecated and will be removed in a future release. " +
					"Please upgrade: https://github.com/GoogleCloudPlatform/policy-library/blob/main/docs/constraint_template_authoring.md#updating-from-v1alpha1-templates",
			)
		}
		c.allConstraints = append(c.allConstraints, u)

	case templateGroup:
		if u.GroupVersionKind().Kind != "ConstraintTemplate" {
			return errors.Errorf("unexpected data type %s in group %s", u.GroupVersionKind(), templateGroup)
		}

		switch u.GroupVersionKind().Version {
		case "v1alpha1":
			glog.Warning(
				"v1alpha1 constraint templates are deprecated and will be removed in a future release. " +
					"Please upgrade: https://github.com/GoogleCloudPlatform/policy-library/blob/main/docs/constraint_template_authoring.md#updating-from-v1alpha1-templates",
			)
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

		if ct.Spec.CRD.Spec.Validation.OpenAPIV3Schema.Type == "" {
			glog.Warning(
				"spec.crd.spec.validation.openAPIV3Schema is missing the type: declaration. " +
					"Please upgrade: https://open-policy-agent.github.io/gatekeeper/website/docs/constrainttemplates#v1-constraint-template",
			)
			ct.Spec.CRD.Spec.Validation.OpenAPIV3Schema.Type = "object"
		}

		if dup, found := c.templateNames[ct.Name]; found {
			return errors.Errorf(
				"ConstraintTemplate %q declared at path %q has duplicate name conflict with template declared at path %q",
				ct.Name, ct.GetAnnotations()[yamlPath], dup.GetAnnotations()[yamlPath])
		}
		c.templateNames[ct.Name] = &ct
		if dup, found := c.templateKinds[ct.Name]; found {
			return errors.Errorf(
				"ConstraintTemplate %q crd kind %q declared at path %q has duplicate kind conflict with template declared at path %q",
				ct.Name, ct.Spec.CRD.Spec.Names.Kind, ct.GetAnnotations()[yamlPath], dup.GetAnnotations()[yamlPath])
		}
		c.templateKinds[ct.Name] = &ct

		for _, target := range ct.Spec.Targets {
			switch target.Target {

			case GCPTargetName:
				c.GCPTemplates = append(c.GCPTemplates, &ct)
			case TFTargetName:
				if u.GroupVersionKind().Version == "v1alpha1" {
					return errors.Errorf("v1alpha1 templates are not supported for terraform templates. Please upgrade.")
				}
				c.TFTemplates = append(c.TFTemplates, &ct)
			case K8STargetName:
				c.K8STemplates = append(c.K8STemplates, &ct)
			default:
				return errors.Errorf("")
			}
		}

	default:
		glog.V(1).Infof("Ignoring %s %s", u.GroupVersionKind(), u.GetName())
	}
	return nil
}

func (c *Configuration) finishLoad() error {
	templates := map[string]string{}
	for _, t := range c.GCPTemplates {
		templates[t.Spec.CRD.Spec.Names.Kind] = gcpConstraint
	}
	for _, t := range c.TFTemplates {
		templates[t.Spec.CRD.Spec.Names.Kind] = tfConstraint
	}
	for _, t := range c.K8STemplates {
		templates[t.Spec.CRD.Spec.Names.Kind] = k8sConstraint
	}

	byTemplate := map[string]map[string]*unstructured.Unstructured{}
	allConstraints := c.allConstraints
	c.allConstraints = nil
	for _, constraint := range allConstraints {
		gvk := constraint.GroupVersionKind()
		if gvk.Version == "v1alpha1" {
			if err := convertLegacyConstraint(constraint); err != nil {
				return fmt.Errorf("failed to convert constraint: %w", err)
			}
		}

		templateConstraints, found := byTemplate[constraint.GetKind()]
		if !found {
			templateConstraints = map[string]*unstructured.Unstructured{}
			byTemplate[constraint.GetKind()] = templateConstraints
		}
		if dup, found := templateConstraints[constraint.GetName()]; found {
			return errors.Errorf(
				"Constraint %q declared at path %q has duplicate name conflict with constraint declared at path %q",
				dup.GetName(), dup.GetAnnotations()[yamlPath], constraint.GetAnnotations()[yamlPath])
		}

		switch templates[gvk.Kind] {
		case gcpConstraint:
			c.GCPConstraints = append(c.GCPConstraints, constraint)
		case tfConstraint:
			c.TFConstraints = append(c.TFConstraints, constraint)
		case k8sConstraint:
			c.K8SConstraints = append(c.K8SConstraints, constraint)
		default:
			return errors.Errorf("constraint %s does not correspond to any templates", gvk)
		}
	}
	return nil
}

// NewConfiguration returns the configuration from the list of provided directories.
func NewConfiguration(dirs []string, libDir string) (*Configuration, error) {
	unstructuredObjects, err := LoadUnstructured(dirs)
	if err != nil {
		return nil, err
	}

	regoLib, err := LoadRegoFiles(libDir)
	if err != nil {
		return nil, err
	}

	return NewConfigurationFromContents(unstructuredObjects, regoLib)
}

// NewConfigurationFromContents returns the configuration from the given
// unstructured objects and the rego library file contents.
// This can be used by code that may not have access to a file system and passes in the contents directly.
func NewConfigurationFromContents(unstructuredObjects []*unstructured.Unstructured, regoLib []string) (*Configuration, error) {
	configuration := newConfiguration()
	configuration.regoLib = regoLib
	var errs multierror.Errors
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

	if err := configuration.finishLoad(); err != nil {
		return nil, errors.Wrapf(err, "config error")
	}

	return configuration, nil
}
