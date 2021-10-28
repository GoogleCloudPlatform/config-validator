# Fuzzing

Fuzzing support using [go-fuzz](https://github.com/dvyukov/go-fuzz).

Basic operation:

```sh
$ cd ~
$ go get -u github.com/dvyukov/go-fuzz/go-fuzz
$ go get -u github.com/dvyukov/go-fuzz/go-fuzz-build
$ cd -
$ cd internal/fuzz/{fuzzer}
# See:
# - https://github.com/dvyukov/go-fuzz/issues/294
# - https://github.com/open-policy-agent/opa/pull/3243
# Not sure why but homedir also complains during typechecking.
$ go-fuzz-build -preserve github.com/OneOfOne/xxhash,k8s.io/client-go/util/homedir
$ go-fuzz
```

## OSS-Fuzz

Fuzzers are automatically run by
[OSS-Fuzz](https://github.com/google/oss-fuzz).

The OSS-Fuzz
[configuration](https://github.com/google/oss-fuzz/blob/master/projects/config-validator)
currently builds the fuzzers under internal/fuzz. Only add fuzzers
(not support packages) in this directory.

Fuzzing results are available at the [OSS-Fuzz console](https://oss-fuzz.com/),
under `config-validator`.
