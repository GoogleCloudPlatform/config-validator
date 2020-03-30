package configs

import (
	"github.com/go-openapi/spec"
)

func refProperty(refURI string) *spec.Schema {
	return &spec.Schema{
		SchemaProps: spec.SchemaProps{
			Ref: spec.MustCreateRef(refURI),
		},
	}
}

var openAPISpecSchema = spec.Schema{
	SchemaProps: spec.SchemaProps{
		Definitions: map[string]spec.Schema{
			"jsonschemaprops": {
				SchemaProps: spec.SchemaProps{
					ID:   "#jsonschemaprops",
					Type: objectType,
					Properties: map[string]spec.Schema{
						"id":                   *spec.StringProperty(),
						"schema":               *spec.StringProperty(),
						"ref":                  *spec.StringProperty(),
						"description":          *spec.StringProperty(),
						"type":                 *spec.StringProperty(),
						"format":               *spec.StringProperty(),
						"title":                *spec.StringProperty(),
						"default":              *refProperty("#json"),
						"maximum":              *spec.Float64Property(),
						"exclusiveMaximum":     *spec.BooleanProperty(),
						"minimum":              *spec.Float64Property(),
						"exclusiveMinimum":     *spec.BooleanProperty(),
						"maxLength":            *spec.Int64Property(),
						"minLength":            *spec.Int64Property(),
						"pattern":              *spec.StringProperty(),
						"maxItems":             *spec.Int64Property(),
						"minItems":             *spec.Int64Property(),
						"uniqueItems":          *spec.BooleanProperty(),
						"multipleOf":           *spec.Float64Property(),
						"enum":                 *spec.ArrayProperty(refProperty("#json")),
						"maxProperties":        *spec.Int64Property(),
						"minProperties":        *spec.Int64Property(),
						"required":             *spec.ArrayProperty(spec.StringProperty()),
						"items":                *refProperty("#jsonschemapropsorarray"),
						"allOf":                *spec.ArrayProperty(refProperty("#jsonschemaprops")),
						"oneOf":                *spec.ArrayProperty(refProperty("#jsonschemaprops")),
						"anyOf":                *spec.ArrayProperty(refProperty("#jsonschemaprops")),
						"not":                  *refProperty("#jsonschemaprops"),
						"properties":           *spec.MapProperty(refProperty("#jsonschemaprops")),
						"additionalProperties": *refProperty("#jsonschemapropsorbool"),
						"patternProperties":    *spec.MapProperty(refProperty("#jsonschemaprops")),
						"dependencies":         *spec.MapProperty(refProperty("#jsonschemapropsorstringarray")),
						"additionalItems":      *refProperty("#jsonschemapropsorbool"),
						"externalDocs":         *refProperty("#externaldocumentation"),
						"example":              *refProperty("#json"),
						"nullable":             *spec.BooleanProperty(),
					},
				},
			},
			"json": {SchemaProps: spec.SchemaProps{ID: "#json"}},
			"externaldocumentation": {
				SchemaProps: spec.SchemaProps{
					ID:   "#externaldocumentation",
					Type: objectType,
					Properties: map[string]spec.Schema{
						"description": *spec.StringProperty(),
						"url":         *spec.StringProperty(),
					},
				},
			},
			"jsonschemapropsorstringarray": {
				SchemaProps: spec.SchemaProps{
					ID:   "#jsonschemapropsorstringarray",
					Type: objectType,
					Properties: map[string]spec.Schema{
						"property": *spec.ArrayProperty(spec.StringProperty()),
						"schema":   *refProperty("#jsonschemaprops"),
					},
				},
			},
			"jsonschemapropsorarray": {
				SchemaProps: spec.SchemaProps{
					ID:   "#jsonschemapropsorarray",
					Type: objectType,
					Properties: map[string]spec.Schema{
						"jSONSchemas": *spec.ArrayProperty(refProperty("#jsonschemaprops")),
						"schema":      *refProperty("#jsonschemaprops"),
					},
				},
			},
			"jsonschemapropsorbool": {
				SchemaProps: spec.SchemaProps{
					ID:   "#jsonschemapropsorbool",
					Type: objectType,
					Properties: map[string]spec.Schema{
						"allows": *spec.BooleanProperty(),
						"schema": *refProperty("#jsonschemaprops"),
					},
				},
			},
		},
	},
}
