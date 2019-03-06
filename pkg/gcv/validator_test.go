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

package gcv

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// TODO(corb): add more tests
//  Errors
//    No dir
//    Invalid dir
//    No config files
//    No read access

const (
	localPolicyDir    = "../../../policies/"
	localPolicyDepDir = "../../../policies/validator/lib"
)

func TestCreateValidatorWithNoOptions(t *testing.T) {
	_, err := NewValidator()
	if err == nil {
		t.Fatal("expected an error since no policy path is provided")
	}
}

func TestDefaultTestDataCreatesValidator(t *testing.T) {
	_, err := NewValidator(generateDefaultTestOptions())
	if err != nil {
		t.Fatal("unexpected error", err)
	}
}

func TestCreate_NoDir(t *testing.T) {
	emptyFolder, err := ioutil.TempDir("", "emptyPolicyDir")
	defer cleanupTmpDir(t, emptyFolder)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewValidator(
		PolicyPath(filepath.Join(emptyFolder, "someDirThatDoesntExist")),
		PolicyLibraryDir(filepath.Join(emptyFolder, "someDirThatDoesntExist")),
	)
	if err == nil {
		t.Fatal("expected a file system error but got no error")
	}
}

func TestCreate_NoReadAccess(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "InvalidAccessTest")
	if err != nil {
		t.Fatal("creating temp dir:", err)
	}
	defer cleanupTmpDir(t, tmpDir)
	// create dir with restrictive permissions
	if err := os.MkdirAll(filepath.Join(tmpDir, "invalidDir"), 0000); err != nil {
		t.Fatal("creating temp dir sub dir:", err)
	}

	_, err = NewValidator(
		PolicyPath(tmpDir),
		PolicyLibraryDir(tmpDir),
	)
	if err == nil {
		t.Fatal("expected a file system error but got no error")
	}
}

func TestCreate_EmptyDir(t *testing.T) {
	policyDir, err := ioutil.TempDir("", "emptyPolicyDir")
	defer cleanupTmpDir(t, policyDir)
	if err != nil {
		t.Fatal(err)
	}
	policyLibDir, err := ioutil.TempDir("", "emptyPolicyDir")
	defer cleanupTmpDir(t, policyLibDir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewValidator(
		PolicyPath(policyDir),
		PolicyLibraryDir(policyLibDir),
	)
	if err != nil {
		t.Fatal("empty dir not expected to provide error: ", err)
	}
}

func cleanupTmpDir(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Log(err)
	}
}

// groupOptions will Groups options in order into a single option.
func groupOptions(options ...Option) Option {
	return func(v *Validator) error {
		for _, option := range options {
			if err := option(v); err != nil {
				return err
			}
		}
		return nil
	}
}

// generateDefaultTestOptions provides a set of default options that allows the successful creation
// of a validator.
func generateDefaultTestOptions() Option {
	// Add default options to this list
	return groupOptions(
		PolicyPath(localPolicyDir),
		PolicyLibraryDir(localPolicyDepDir),
	)
}