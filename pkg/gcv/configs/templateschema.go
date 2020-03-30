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

package configs

import (
	"github.com/go-openapi/spec"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

var (
	objectType = spec.StringOrArray{"object"}
)

var definitions = map[string]spec.Schema{
	"stringstringmap": {
		SchemaProps: spec.SchemaProps{
			ID:   "#stringstringmap",
			Type: objectType,
			PatternProperties: map[string]spec.Schema{
				".*": *spec.StringProperty(),
			},
		},
	},
	"metadata": {
		SchemaProps: spec.SchemaProps{
			ID:       "#metadata",
			Type:     objectType,
			Required: []string{"name"},
			Properties: map[string]spec.Schema{
				"name":        *spec.StringProperty(),
				"labels":      *spec.MapProperty(spec.StringProperty()),
				"annotations": *spec.MapProperty(spec.StringProperty()),
			},
		},
	},
	"speccrd": {
		SchemaProps: spec.SchemaProps{
			ID:                   "#speccrd",
			AdditionalProperties: &spec.SchemaOrBool{Allows: false},
			Required:             []string{"spec"},
			Properties: map[string]spec.Schema{
				"spec": {
					SchemaProps: spec.SchemaProps{
						AdditionalProperties: &spec.SchemaOrBool{Allows: false},
						Required:             []string{"names"},
						Properties: map[string]spec.Schema{
							"names": {
								SchemaProps: spec.SchemaProps{
									AdditionalProperties: &spec.SchemaOrBool{Allows: false},
									Required:             []string{"kind"},
									Properties: map[string]spec.Schema{
										"kind": *spec.StringProperty(),
									},
								},
							},
							"validation": openAPISpecSchema,
						},
					},
				},
			},
		},
	},
	"alphav1spec": {
		SchemaProps: spec.SchemaProps{
			Type:                 objectType,
			AdditionalProperties: &spec.SchemaOrBool{Allows: false},
			Required:             []string{"crd", "targets"},
			Properties: map[string]spec.Schema{
				"crd": *refProperty("#speccrd"),
				"targets": *spec.MapProperty(&spec.Schema{
					SchemaProps: spec.SchemaProps{
						Type:                 objectType,
						AdditionalProperties: &spec.SchemaOrBool{Allows: false},
						Required:             []string{"rego"},
						Properties: map[string]spec.Schema{
							"rego": *spec.StringProperty(),
							"libs": *spec.ArrayProperty(spec.StringProperty()),
						},
					},
				}),
			},
		},
	},
	"betav1spec": {
		SchemaProps: spec.SchemaProps{
			Type:                 objectType,
			AdditionalProperties: &spec.SchemaOrBool{Allows: false},
			Required:             []string{"crd", "targets"},
			Properties: map[string]spec.Schema{
				"crd": *refProperty("#speccrd"),
				// convert to array here.
				"targets": *spec.ArrayProperty(&spec.Schema{
					VendorExtensible: spec.VendorExtensible{},
					SchemaProps: spec.SchemaProps{
						Type:                 objectType,
						AdditionalProperties: &spec.SchemaOrBool{Allows: false},
						Required:             []string{"target", "rego"},
						Properties: map[string]spec.Schema{
							"target": *spec.StringProperty(),
							"rego":   *spec.StringProperty(),
							"libs":   *spec.ArrayProperty(spec.StringProperty()),
						},
					},
				}),
			},
		},
	},
}

// configValidatorV1Alpha1Schema is the legacy config validator schema for CF-like templates.  Note that there's
// a subtle difference between this where "targets" is a map rather than an array.
var configValidatorV1Alpha1Schema = spec.Schema{
	SchemaProps: spec.SchemaProps{
		Definitions:          definitions,
		AdditionalProperties: &spec.SchemaOrBool{Allows: true},
		Properties: map[string]spec.Schema{
			"metadata": *refProperty("#metadata"),
			"spec":     *refProperty("#alphav1spec"),
		},
	},
}

var configValidatorV1Alpha1SchemaValidator = validate.NewSchemaValidator(
	&configValidatorV1Alpha1Schema, nil, "", strfmt.Default)

var configValidatorV1Beta1Schema = spec.Schema{
	SchemaProps: spec.SchemaProps{
		Definitions:          definitions,
		AdditionalProperties: &spec.SchemaOrBool{Allows: true},
		Properties: map[string]spec.Schema{
			"metadata": *refProperty("#metadata"),
			"spec":     *refProperty("#betav1spec"),
		},
	},
}

var configValidatorV1Beta1SchemaValidator = validate.NewSchemaValidator(
	&configValidatorV1Beta1Schema, nil, "", strfmt.Default)
