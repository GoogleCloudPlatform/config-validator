package configs

import (
	"github.com/go-openapi/spec"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

var configValidatorV1Beta1Schema = spec.Schema{
	SchemaProps: spec.SchemaProps{
		AdditionalProperties: &spec.SchemaOrBool{Allows: true},
		Properties: map[string]spec.Schema{
			"metadata": {
				SchemaProps: spec.SchemaProps{
					Type:     objectType,
					Required: []string{"name"},
					Properties: map[string]spec.Schema{
						"name": *spec.StringProperty(),
					},
				},
			},
			"spec": {
				SchemaProps: spec.SchemaProps{
					Type:                 objectType,
					AdditionalProperties: &spec.SchemaOrBool{Allows: false},
					Required:             []string{"crd", "targets"},
					Properties: map[string]spec.Schema{
						"crd": {
							SchemaProps: spec.SchemaProps{
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
												"validation": {
													// TODO: use k8s.io/kubernetes/api/openapi-spec/swagger.json
													// to generate an openapi spec.
													SchemaProps: spec.SchemaProps{
														AdditionalProperties: &spec.SchemaOrBool{Allows: true},
													},
												},
											},
										},
									},
								},
							},
						},
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
							SwaggerSchemaProps: spec.SwaggerSchemaProps{},
							ExtraProps:         nil,
						}),
					},
				},
			},
		},
	},
}

var configValidatorV1Beta1SchemaValidator = validate.NewSchemaValidator(
	&configValidatorV1Beta1Schema, nil, "", strfmt.Default)
