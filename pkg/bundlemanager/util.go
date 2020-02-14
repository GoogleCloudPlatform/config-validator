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

package bundlemanager

import (
	"sort"
	"strings"
)

var bundlePrefix = "bundles.validator.forsetisecurity.org/"

// HasBundleAnnotation returns true if the given annotation key relates to a bundle.
func HasBundleAnnotation(key string) bool {
	return strings.HasPrefix(key, bundlePrefix)
}

// bundleControls returns all the bundle related annotations from an object
func bundleControls(obj Object) map[string]string {
	tags := map[string]string{}
	for k, v := range obj.GetAnnotations() {
		if HasBundleAnnotation(k) {
			tags[k] = v
		}
	}
	return tags
}

// allBundles returns all the bundle related annotation keys from the object
func allBundles(objs []Object) []string {
	var tags []string
	for _, obj := range objs {
		for k := range bundleControls(obj) {
			tags = append(tags, k)
		}
	}
	return uniqueSorted(tags)
}

// uniqueSorted returns a sorted slice of all unique elements in m.
func uniqueSorted(m []string) []string {
	keySet := map[string]struct{}{}
	for _, k := range m {
		keySet[k] = struct{}{}
	}
	return sortedKeys(keySet)
}

// sortedKeys returns a sorted slice of keys from the input map.
func sortedKeys(keySet map[string]struct{}) []string {
	var keys []string
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// filter returns a slice of objects from objs where predicate returns true when evaluating the
// object
func filter(objs []Object, predicate func(Object) bool) []Object {
	var filtered []Object
	for _, obj := range objs {
		if predicate(obj) {
			filtered = append(filtered, obj)
		}
	}
	return filtered
}

// inBundle returns a function that evaluates if an object belongs to a given bundle.
func inBundle(bundle string) func(Object) bool {
	return func(ct Object) bool {
		_, ok := ct.GetAnnotations()[bundle]
		return ok
	}
}

// notBundled returns true if an object is not associated with any bundles.
func notBundled() func(Object) bool {
	return func(ct Object) bool {
		return len(bundleControls(ct)) == 0
	}
}

// getControls returns a slice of all controls found in objects.
func getControls(cts []Object, bundle string) []string {
	return mapObjectsToStrs(cts, func(ct Object) string {
		return ct.GetAnnotations()[bundle]
	})
}

// getNames returns a slice of the names of all input objects
func getNames(objs []Object) []string {
	return mapObjectsToStrs(objs, func(ct Object) string {
		return ct.GetName()
	})
}

// mapObjectsToStrs takes a slice of objects and a function that transforms an object to a string
// then returns a sorted slice of the resulting strings
func mapObjectsToStrs(
	objs []Object,
	fn func(Object) string) []string {
	var strs []string
	for _, ct := range objs {
		strs = append(strs, fn(ct))
	}
	sort.Strings(strs)
	return strs
}

// hasName returns a function that returns true if the object matches name
func hasName(name string) func(Object) bool {
	return func(ct Object) bool {
		return ct.GetName() == name
	}
}
