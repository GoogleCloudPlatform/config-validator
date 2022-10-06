# Config Validator

[![OSS-Fuzz Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/config-validator.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:config-validator)

This is a Golang library which provides functionality to evaluate
GCP resources against Rego-based policies. It can be used to add
config policy support to new projects without having to integrate
Rego parsing directly.

For information on setting up Config Validator to secure your environment,
see the [User Guide](https://github.com/GoogleCloudPlatform/policy-library/blob/main/docs/user_guide.md).

## Development
### Available Commands

```sh
make proto     rebuilt protobuf library
make pyproto   build python gRPC client stub and proto lib
make test      run unit tests
make build     rebuilt and reformat
make release   build binaries
make clear     delete binaries
make format    reformat code
```

## Disclaimer
This is not an officially supported Google product.
