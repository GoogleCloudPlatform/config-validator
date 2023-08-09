PROTO_DOCKER_IMAGE=gcv-proto-builder
PLATFORMS := linux windows darwin
BUILD_DIR=./bin
NAME=config-validator

# Build docker image used for generating proto files
.PHONY: proto-builder
proto-builder:
	docker build -t $(PROTO_DOCKER_IMAGE) -f ./build/proto/Dockerfile .

# Generate validator.proto
.PHONY: proto
proto: proto-builder
	docker run \
		-v `pwd`:/go/src/github.com/GoogleCloudPlatform/config-validator \
		$(PROTO_DOCKER_IMAGE) \
		protoc -I/proto -I./api --go_out=plugins=grpc:./pkg/api ./api/validator.proto
	go run cloud.google.com/go/internal/aliasfix/cmd/aliasfix@v0.0.0-20230804212214-b30a7f4a520c .
	go mod tidy
	sed -i 's/\"google.golang.org\/genproto\/googleapis\/cloud\/orgpolicy\/v1\"/\"cloud.google.com\/go\/orgpolicy\/apiv1\/orgpolicypb\"/g' pkg/api/validator/validator.pb.go

# Generate validator.proto for Python
.PHONY: pyproto
pyproto:
	mkdir -p build-grpc
	docker run \
		-v `pwd`:/go/src/github.com/GoogleCloudPlatform/config-validator \
		$(PROTO_DOCKER_IMAGE) \
		python -m grpc_tools.protoc -I/proto -I./api --python_out=./build-grpc --grpc_python_out=./build-grpc ./api/validator.proto
	@echo "Generated files available in ./build-grpc"

.PHONY: test
test:
	GO111MODULE=on go test ./...

# Format source code, generate protos, and build policy-tool and server
.PHONY: build
build: format proto tools

# Build the Config Validator Docker iamge
.PHONY: docker_build
docker_build: build
	docker build -t gcr.io/config-validator/config-validator:latest .

# Build and run the Config Validator Docker image listening on port 50052
# Set env var POLICY_LIBRARY_DIR to the local path of the policy library
.PHONY: docker_run
docker_run: guard-POLICY_LIBRARY_DIR docker_build
	docker run --rm -p 50052:50052 --name config-validator \
		-v $(POLICY_LIBRARY_DIR):/policy-library \
		gcr.io/config-validator/config-validator:latest \
		--policyPath='/policy-library/policies' \
		--policyLibraryPath='/policy-library/lib' \
		-port=50052 \
		-v 7 \
		-alsologtostderr

.PHONY: release
release: $(PLATFORMS)

.PHONY: $(PLATFORMS)
$(PLATFORMS):
	GO111MODULE=on GOOS=$@ GOARCH=amd64 CGO_ENABLED=0 go build -o "${BUILD_DIR}/${NAME}-$@-amd64" cmd/server/main.go

.PHONY: clean
clean:
	rm bin/${NAME}*

# Automatically format Go source code
.PHONY: format
format:
	go fmt ./...

# Build policy-tool and server
.PHONY: tools
tools:
	go build ./cmd/...

POLICY_TOOLS := $(foreach p,$(PLATFORMS),policy-tool-$(p))
.PHONY: $(POLICY_TOOLS)
$(POLICY_TOOLS):
	GO111MODULE=on GOOS=$(subst policy-tool-,,$@) GOARCH=amd64 CGO_ENABLED=0 \
		go build -o "${BUILD_DIR}/$@-amd64" cmd/policy-tool/policy-tool.go

DIRTY := $(shell git diff --no-ext-diff --quiet --exit-code || echo -n -dirty)
TAG := $(shell git log -n1 --pretty=format:%h)
IMAGE := gcr.io/config-validator/policy-tool:commit-$(TAG)$(DIRTY)
policy-tool-docker:
	docker build -t $(IMAGE) -f ./build/policy-tool/Dockerfile .
	docker push $(IMAGE)

# Helper target to require an env var to be set
guard-%:
	@ if [ "${${*}}" = "" ]; then \
		echo "Environment variable $* not set"; \
		exit 1; \
  fi
