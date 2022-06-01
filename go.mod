module github.com/GoogleCloudPlatform/config-validator

go 1.12

require (
	cloud.google.com/go/storage v1.10.0
	github.com/davecgh/go-spew v1.1.1
	github.com/ghodss/yaml v1.0.0
	github.com/go-logr/zapr v0.1.1 // indirect
	github.com/go-openapi/spec v0.19.4
	github.com/go-openapi/strfmt v0.19.3
	github.com/go-openapi/validate v0.19.5
	github.com/gogo/protobuf v1.3.2
	github.com/golang/glog v1.0.0
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.7
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/hashicorp/go-multierror v1.1.1
	github.com/open-policy-agent/frameworks/constraint v0.0.0-20210422220901-804ff2ee8b4f
	github.com/open-policy-agent/gatekeeper v0.0.0-20200130050101-a7990e5bc83a
	github.com/open-policy-agent/opa v0.40.0
	github.com/pkg/errors v0.9.1
	github.com/smallfish/simpleyaml v0.0.0-20170911015856-a32031077861
	github.com/spf13/cobra v1.4.0
	github.com/spf13/pflag v1.0.5
	go.opentelemetry.io/otel/internal/metric v0.27.0 // indirect
	google.golang.org/api v0.44.0
	google.golang.org/genproto v0.0.0-20220107163113-42d7afdf6368
	google.golang.org/grpc v1.46.0
	k8s.io/api v0.22.5
	k8s.io/apiextensions-apiserver v0.17.2
	k8s.io/apimachinery v0.22.5
	k8s.io/cli-runtime v0.17.2
	k8s.io/kubectl v0.17.2
)
