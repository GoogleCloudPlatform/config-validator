PROTO_DOCKER_IMAGE=gcv-proto-builder
PLATFORMS := linux windows darwin
BUILD_DIR=./bin
NAME=config-validator

.PHONY: proto-builder
proto-builder:
	docker build -t $(PROTO_DOCKER_IMAGE) -f ./build/proto/Dockerfile .

.PHONY: proto
proto: proto-builder
	docker run \
		-v `pwd`:/go/src/github.com/forseti-security/config-validator \
		$(PROTO_DOCKER_IMAGE) \
		protoc -I/proto -I./api --go_out=plugins=grpc:./pkg/api/validator ./api/validator.proto

.PHONY: proto
proto: proto-builder
	docker run \
		-v `pwd`:/go/src/github.com/forseti-security/config-validator \
		$(PROTO_DOCKER_IMAGE) \
		protoc -I/proto -I./api --python_out=plugins=grpc:./pkg/api/validator ./api/validator.proto

.PHONY: test
test:
	GO111MODULE=on go test ./...

.PHONY: build
build: format proto tools

.PHONY: release
release: $(PLATFORMS)

.PHONY: $(PLATFORMS)
$(PLATFORMS):
	GO111MODULE=on GOOS=$@ GOARCH=amd64 CGO_ENABLED=0 go build -o "${BUILD_DIR}/${NAME}-$@-amd64" cmd/server/main.go

.PHONY: clean
clean:
	rm bin/${NAME}*

.PHONY: format
format:
	go fmt ./...

.PHONY: tools
tools:
	go build ./cmd/...

POLICY_TOOLS := $(foreach p,$(PLATFORMS),policy-tool-$(p))
.PHONY: $(POLICY_TOOLS)
$(POLICY_TOOLS):
	GO111MODULE=on GOOS=$(subst policy-tool-,,$@) GOARCH=amd64 CGO_ENABLED=0 \
		go build -o "${BUILD_DIR}/$@-amd64" cmd/policy-tool/policy-tool.go

policy-tool-docker:
	docker build -t gcr.io/config-validator/policy-tool -f ./build/policy-tool/Dockerfile .

