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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/forseti-security/config-validator/pkg/api/validator"
	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"github.com/golang/protobuf/jsonpb"
	pb "github.com/golang/protobuf/ptypes/struct"
	cfapis "github.com/open-policy-agent/frameworks/constraint/pkg/apis"
	cfv1alpha1 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1alpha1"
	cftemplates "github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/regorewriter"
	"github.com/pkg/errors"
	"github.com/smallfish/simpleyaml"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/kubectl/pkg/scheme"

	"google.golang.org/api/iterator"

	"cloud.google.com/go/storage"
)

const (
	logRequestsVerboseLevel = 2
)

func init() {
	utilruntime.Must(cfapis.AddToScheme(scheme.Scheme))
}

func configGCSClient() (client *storage.Client) {
	ctx := context.Background()

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	return client
}

type yamlFile struct {
	source       string // helpful information to rediscover this data
	yaml         *simpleyaml.Yaml
	fileContents []byte
}

const (
	validTemplateGroup   = "templates.gatekeeper.sh/v1alpha1"
	validConstraintGroup = "constraints.gatekeeper.sh/v1alpha1"
	constraintGroup      = "constraints.gatekeeper.sh"
	expectedTarget       = "validation.gcp.forsetisecurity.org"
	yamlPath             = expectedTarget + "/yamlpath"
)

var (
	// templateGK is the GroupKind for ConstraintTemplate types.
	templateGK = schema.GroupKind{Group: cfv1alpha1.SchemeGroupVersion.Group, Kind: "ConstraintTemplate"}
	client     = configGCSClient()
)

// UnclassifiedConfig stores loosely parsed information not specific to constraints or templates.
type UnclassifiedConfig struct {
	Group        string
	MetadataName string
	Kind         string
	Yaml         *simpleyaml.Yaml
	// keep the file path to help debug logging
	FilePath string
	// Preserve the raw user data to forward into rego
	// This prevents any data loss issues from going though parsing libraries.
	RawFile string
}

// ConstraintTemplate stores parsed information including the raw data.
type ConstraintTemplate struct {
	Confg *UnclassifiedConfig
	// This is the kind that this template generates.
	GeneratedKind string
	Rego          string
}

// Constraint stores parsed information including the raw data.
type Constraint struct {
	Confg *UnclassifiedConfig
}

// AsInterface returns the the config data as a structured golang object. This uses yaml.Unmarshal to create this object.
func (c *UnclassifiedConfig) AsInterface() (interface{}, error) {
	// Use yaml.Unmarshal to create a proper golang object that maintains the same structure
	var f interface{}
	if err := yaml.Unmarshal([]byte(c.RawFile), &f); err != nil {
		return nil, errors.Wrap(err, "converting from yaml")
	}
	return f, nil
}

// asConstraint attempts to convert to constraint
// Returns:
//   *Constraint: only set if valid constraint
//   bool: (always set) if this is a constraint
func asConstraint(data *UnclassifiedConfig) (*Constraint, error) {
	// There is no validation matching this constraint to the template here that happens after
	// basic parsing has happened when we have more context.
	if data.Group != validConstraintGroup {
		return nil, fmt.Errorf("group expected to be %s not %s", validConstraintGroup, data.Group)
	}
	if data.Kind == "ConstraintTemplate" {
		return nil, fmt.Errorf("kind should not be ConstraintTemplate")
	}
	return &Constraint{
		Confg: data,
	}, nil
}

// AsProto returns the constraint a Kubernetes proto
func (c *Constraint) AsProto() (*validator.Constraint, error) {
	ci, err := c.Confg.AsInterface()
	if err != nil {
		return nil, errors.Wrap(err, "converting to proto")
	}
	cp := &validator.Constraint{}

	metadata, err := convertToProtoVal(ci.(map[string]interface{})["metadata"])
	if err != nil {
		return nil, errors.Wrap(err, "converting to proto")
	}
	cp.Metadata = metadata

	return cp, nil
}

// asConstraintTemplate attempts to convert to template
// Returns:
//   *ConstraintTemplate: only set if valid template
//   bool: (always set) if this is a template
func asConstraintTemplate(data *UnclassifiedConfig) (*ConstraintTemplate, error) {
	if data.Group != validTemplateGroup {
		return nil, fmt.Errorf("group expected to be %s not %s", validTemplateGroup, data.Group)
	}
	if data.Kind != "ConstraintTemplate" {
		return nil, fmt.Errorf("kind expected to be ConstraintTemplate not %s", data.Kind)
	}
	generatedKind, err := data.Yaml.GetPath("spec", "crd", "spec", "names", "kind").String()
	if err != nil {
		return nil, err // field expected to exist
	}
	rego, err := extractRego(data.Yaml)
	if err != nil {
		return nil, err // field expected to exist
	}
	return &ConstraintTemplate{
		Confg:         data,
		GeneratedKind: generatedKind,
		Rego:          rego,
	}, nil
}

func extractRego(yaml *simpleyaml.Yaml) (string, error) {
	targets := yaml.GetPath("spec", "targets")
	if !targets.IsArray() {
		// Old format looks like the following
		// targets:
		//   validation.gcp.forsetisecurity.org:
		//     rego:
		return targets.GetPath(expectedTarget, "rego").String()
	}
	// New format looks like the following
	// targets:
	//  - target: validation.gcp.forsetisecurity.org
	//    rego:
	size, err := targets.GetArraySize()
	if err != nil {
		return "", err
	}
	for i := 0; i < size; i++ {
		target := targets.GetIndex(i)
		targetString, err := target.Get("target").String()
		if err != nil {
			return "", err
		}
		if targetString == expectedTarget {
			return target.Get("rego").String()
		}
	}

	return "", status.Error(codes.InvalidArgument, "Unable to locate rego field in constraint template")
}

func arrayFilterSuffix(arr []string, suffix string) []string {
	var filteredList []string
	for _, s := range arr {
		if strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix)) {
			filteredList = append(filteredList, s)
		}
	}
	return filteredList
}

// listFiles returns a list of files under a dir either locally or in GCS. Errors will be grpc errors.
func listFiles(dir string) ([]string, error) {
	var files []string
	var err error

	if strings.HasPrefix(dir, "gs://") {
		files, err = listFilesGCS(dir)
	} else {
		files, err = listFilesLocal(dir)
	}
	if err != nil {
		return nil, err
	}
	fmt.Printf("Number of files: %d", len(files))
	for _, file := range files {
		glog.V(logRequestsVerboseLevel).Infof("File in list: %s", file)

	}

	return files, nil
}

// listFilesLocal returns a list of files under a dir. Errors will be grpc errors.
func listFilesLocal(dir string) ([]string, error) {
	var files []string

	visit := func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return errors.Wrapf(err, "error visiting path %s", path)
		}
		if !f.IsDir() {
			files = append(files, path)
		}
		return nil
	}

	err := filepath.Walk(dir, visit)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return files, nil
}

// listFilesGCS returns a list of files under a dir in a GCS bucket. Errors will be grpc errors.
func listFilesGCS(bucketPath string) ([]string, error) {
	ctx := context.Background()
	var files []string
	bucket, prefix := parseBucketPath(bucketPath)

	it := client.Bucket(bucket).Objects(ctx, &storage.Query{
		Prefix: prefix,
	})
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		fileName := "gs://" + bucket + "/" + attrs.Name
		files = append(files, fileName)
	}
	return files, nil
}

// ListYAMLFiles returns a list of YAML files under a dir. Errors will be grpc errors.
func ListYAMLFiles(dir string) ([]string, error) {
	return ListYAMLFilesD([]string{dir})
}

// ListYAMLFiles returns a list of YAML files under a dir. Errors will be grpc errors.
func ListYAMLFilesD(dirs []string) ([]string, error) {
	var files []string
	for _, dir := range dirs {
		dirFiles, err := listFiles(dir)
		if err != nil {
			return nil, err
		}
		files = append(files, dirFiles...)
	}
	return arrayFilterSuffix(files, ".yaml"), nil
}

//ListRegoFiles returns a list of rego files under a dir. Errors will be grpc errors.
func ListRegoFiles(dir string) ([]string, error) {
	files, err := listFiles(dir)
	if err != nil {
		return nil, err
	}
	return arrayFilterSuffix(files, ".rego"), nil
}

// convertYAMLToUnclassifiedConfig converts yaml file to an unclassified config, if expected fields don't exist, a log message is printed and the config is skipped.
func convertYAMLToUnclassifiedConfig(config *yamlFile) (*UnclassifiedConfig, error) {
	kind, err := config.yaml.Get("kind").String()
	if err != nil {
		return nil, fmt.Errorf("error in converting %s: %v", config.source, err)
	}
	group, err := config.yaml.Get("apiVersion").String()
	if err != nil {
		return nil, fmt.Errorf("error in converting %s: %v", config.source, err)
	}
	metadataName, err := config.yaml.GetPath("metadata", "name").String()
	if err != nil {
		return nil, fmt.Errorf("error in converting %s: %v", config.source, err)
	}
	convertedConfig := &UnclassifiedConfig{
		Group:        group,
		MetadataName: metadataName,
		Kind:         kind,
		Yaml:         config.yaml,
		FilePath:     config.source,
		RawFile:      string(config.fileContents),
	}
	return convertedConfig, nil
}

// Returns either a *ConstraintTemplate or a *Constraint or an error
// dataSource should be helpful documentation to help rediscover the source of this information.
func CategorizeYAMLFile(data []byte, dataSource string) (interface{}, error) {
	y, err := simpleyaml.NewYaml(data)
	if err != nil {
		return nil, err
	}
	unclassified, err := convertYAMLToUnclassifiedConfig(&yamlFile{
		yaml:         y,
		fileContents: data,
		source:       dataSource,
	})
	if err != nil {
		return nil, err
	}
	switch unclassified.Group {
	case validTemplateGroup:
		return asConstraintTemplate(unclassified)
	case validConstraintGroup:
		return asConstraint(unclassified)
	}
	return nil, fmt.Errorf("unable to determine configuration type for data %s", dataSource)
}

func convertToProtoVal(from interface{}) (*pb.Value, error) {
	to := &pb.Value{}
	jsn, err := json.Marshal(from)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling to json")
	}

	if err := jsonpb.UnmarshalString(string(jsn), to); err != nil {
		return nil, errors.Wrap(err, "unmarshalling to proto")
	}

	return to, nil
}

func loadUnstructured(dirs []string) ([]*unstructured.Unstructured, error) {
	var contents []byte
	var err error

	files, err := ListYAMLFilesD(dirs)
	if err != nil {
		return nil, err
	}

	var yamlDocs []*unstructured.Unstructured
	for _, file := range files {
		if strings.HasPrefix(file, "gs://") {
			contents, err = loadFileGCS(file)
		} else {
			contents, err = loadFileLocal(file)
		}

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

func convertLegacyConstraint(u *unstructured.Unstructured) error {
	u.SetName(strings.Replace(u.GetName(), "_", "-", -1))
	return nil
}

// Configuration represents the configuration files fed into FCV.
type Configuration struct {
	Templates   []*cftemplates.ConstraintTemplate
	Constraints []*unstructured.Unstructured
	Libs        []string
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

		if strings.HasPrefix(filePath, "gs://") {
			glog.V(2).Infof("Loading rego file from GCS: %s", filePath)
			content, err = loadFileGCS(filePath)
		} else {
			glog.V(2).Infof("Loading rego file from local: %s", filePath)
			content, err = loadFileLocal(filePath)
		}

		if err != nil {
			return nil, errors.Wrapf(err, "unable to read file %s", filePath)
		}
		libs = append(libs, string(content))
	}
	return libs, nil
}

func loadFileLocal(filePath string) ([]byte, error) {
	fileBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to read file %s", filePath)
	}
	return fileBytes, nil
}

func loadFileGCS(bucketPath string) ([]byte, error) {
	ctx := context.Background()

	bucket, object := parseBucketPath(bucketPath)
	rc, err := client.Bucket(bucket).Object(object).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	data, err := ioutil.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	return data, nil
	// [END download_file]
}

func parseBucketPath(bucketPath string) (string, string) {
	bucketPath = strings.ReplaceAll(bucketPath, "gs://", "")

	delim := "/"

	pathPieces := strings.Split(bucketPath, delim)

	bucket := pathPieces[0]
	path := strings.Join(pathPieces[1:], delim)

	return bucket, path
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

	var templates []*cftemplates.ConstraintTemplate
	var constraints []*unstructured.Unstructured
	converter := runtime.ObjectConvertor(scheme.Scheme)
	for _, u := range unstructuredObjects {
		switch {
		case u.GroupVersionKind().GroupKind() == templateGK:
			if err := convertLegacyConstraintTemplate(u, regoLib); err != nil {
				return nil, errors.Wrapf(err, "failed to handle legacy CT")
			}

			groupVersioner := runtime.GroupVersioner(schema.GroupVersions(scheme.Scheme.PrioritizedVersionsAllGroups()))
			obj, err := converter.ConvertToVersion(u, groupVersioner)
			if err != nil {
				return nil, errors.Wrap(err, "failed to convert CT to versioned")
			}

			var ct cftemplates.ConstraintTemplate
			if err := converter.Convert(obj, &ct, nil); err != nil {
				return nil, errors.Wrapf(err, "failed to convert to constraint template internal struct")
			}

			templates = append(templates, &ct)
		case u.GroupVersionKind().Group == constraintGroup:
			if err := convertLegacyConstraint(u); err != nil {
				return nil, errors.Wrapf(err, "failed to convert constraint")
			}
			constraints = append(constraints, u)
		default:
			return nil, errors.Errorf("unexpected data type %s in file %s", u.GroupVersionKind(), u.GetAnnotations()[yamlPath])
		}
	}
	return &Configuration{Templates: templates, Constraints: constraints}, nil
}
