# Fuzzing

Fuzzing support using [go-fuzz](https://github.com/dvyukov/go-fuzz).

Basic operation:

```sh
$ cd ~
$ go get -u github.com/dvyukov/go-fuzz/go-fuzz@latest
$ go get -u github.com/dvyukov/go-fuzz/go-fuzz-build@latest
$ go get -u github.com/dvyukov/go-fuzz/go-fuzz-dep@latest
$ cd -
$ cd internal/fuzz/{fuzzer}
$ go-fuzz-build go114-fuzz-build github.com/GoogleCloudPlatform/config-validator/internal/fuzz/{fuzzer}
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
