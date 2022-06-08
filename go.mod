module github.com/GoogleCloudPlatform/config-validator

go 1.17

// Prevent otel dependencies from getting out of sync.
// Cannot be upgraded until k8s.io/component-base uses a more recent version of
// opentelemetry.
replace (
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp => go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.20.0
	go.opentelemetry.io/otel => go.opentelemetry.io/otel v0.20.0
	go.opentelemetry.io/otel/metric => go.opentelemetry.io/otel/metric v0.20.0
	go.opentelemetry.io/otel/sdk => go.opentelemetry.io/otel/sdk v0.20.0
	go.opentelemetry.io/otel/trace => go.opentelemetry.io/otel/trace v0.20.0
	go.opentelemetry.io/proto/otlp => go.opentelemetry.io/proto/otlp v0.7.0
)

require (
	cloud.google.com/go/storage v1.8.0
	github.com/davecgh/go-spew v1.1.1
	github.com/ghodss/yaml v1.0.0
	github.com/go-openapi/spec v0.19.5
	github.com/go-openapi/strfmt v0.19.3
	github.com/go-openapi/validate v0.19.5
	github.com/gogo/protobuf v1.3.2
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/protobuf v1.4.3
	github.com/google/go-cmp v0.5.4
	github.com/hashicorp/go-multierror v1.1.1
	github.com/open-policy-agent/frameworks/constraint v0.0.0-20210803013759-9f2691290092
	github.com/open-policy-agent/gatekeeper v0.0.0-20200130050101-a7990e5bc83a
	github.com/pkg/errors v0.9.1
	github.com/smallfish/simpleyaml v0.0.0-20170911015856-a32031077861
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	google.golang.org/api v0.29.0
	google.golang.org/genproto v0.0.0-20201110150050-8816d57aaa9a
	google.golang.org/grpc v1.29.1
	k8s.io/api v0.20.2
	k8s.io/apiextensions-apiserver v0.20.2
	k8s.io/apimachinery v0.20.2
	k8s.io/kubectl v0.20.2
)

require (
	github.com/go-logr/zapr v0.2.0 // indirect
	github.com/open-policy-agent/opa v0.29.3 // indirect
)
