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

// Package configs helps with loading and parsing configuration files
package configs

import (
	"context"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	client = configGCSClient()
)

func configGCSClient() (client *storage.Client) {
	ctx := context.Background()

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	return client
}

type file interface {
	read() ([]byte, error)
	String() string
}

type localFile struct {
	path string
}

type gcsFile struct {
	bucket string
	path   string
}

type dir interface {
	listFiles() ([]string, error)
}

type gcsDir struct {
	path string
}

type localDir struct {
	path string
}

func newFile(name string) (file, error) {
	fileURL, err := url.Parse(name)
	if err != nil {
		return nil, err
	}

	if fileURL.Scheme == "gs" {
		configFile := new(gcsFile)
		configFile.bucket = fileURL.Host
		configFile.path = strings.Replace(fileURL.Path, "/", "", 1)
		return configFile, nil
	}

	configFile := new(localFile)
	configFile.path = name

	return configFile, nil
}

func (f *localFile) read() ([]byte, error) {
	glog.V(2).Infof("Loading local file at path %s", f.path)
	fileBytes, err := ioutil.ReadFile(f.path)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to read file %s", f.path)
	}
	return fileBytes, nil
}

func (f *localFile) String() string {
	return f.path
}

func (f *gcsFile) read() ([]byte, error) {
	ctx := context.Background()
	glog.V(2).Infof("Loading file in GCS at path %s", f.path)

	rc, err := client.Bucket(f.bucket).Object(f.path).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	data, err := ioutil.ReadAll(rc)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to read file %s from bucket %s", f.path, f.bucket)
	}
	return data, nil
	// [END download_file]
}

func (f *gcsFile) String() string {
	return f.path
}

func newDir(name string) (dir, error) {
	dirURL, err := url.Parse(name)
	if err != nil {
		return nil, err
	}

	if dirURL.Scheme == "gs" {
		configDir := new(gcsDir)
		configDir.path = name
		return configDir, nil
	}

	configDir := new(localDir)
	configDir.path = name

	return configDir, nil
}

func (d *localDir) listFiles() ([]string, error) {
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

	err := filepath.Walk(d.path, visit)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return files, nil
}

func (d *gcsDir) listFiles() ([]string, error) {
	var files []string
	ctx := context.Background()
	dirURL, err := url.Parse(d.path)

	if err != nil {
		return nil, errors.Wrapf(err, "error visiting path %s", d.path)
	}

	bucket := dirURL.Host
	prefix := strings.Replace(dirURL.Path, "/", "", 1)

	it := client.Bucket(bucket).Objects(ctx, &storage.Query{
		Prefix: prefix,
	})
	glog.V(2).Infof("Listing files in GCS at host %s and path %s", bucket, prefix)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		fileName := "gs://" + bucket + "/" + attrs.Name
		glog.V(2).Infof("Listing GCS Object %s", fileName)

		files = append(files, fileName)
	}
	return files, nil
}
