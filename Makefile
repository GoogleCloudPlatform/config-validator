PROTO_DOCKER_IMAGE=gcv-proto-builder
PLATFORMS := linux windows darwin
BUILD_DIR=./bin
NAME=constraint-validator

proto-builder:
	docker build -t $(PROTO_DOCKER_IMAGE) -f ./build/proto/Dockerfile .

proto: proto-builder
	docker run \
		-v `pwd`:/go/src/github.com/forseti-security/config-validator \
		$(PROTO_DOCKER_IMAGE) \
		protoc -I/proto -I./api --go_out=plugins=grpc:./pkg/api/validator ./api/validator.proto

test:
	GO111MODULE=on go test ./...

build:
	GO111MODULE=on go build -o ${BUILD_DIR}/${NAME}

release: $(PLATFORMS)

$(PLATFORMS):
	GO111MODULE=on GOOS=$@ GOARCH=amd64 go build -o "${BUILD_DIR}/${NAME}-$@-amd64" .

clean:
	rm bin/${NAME}*

reformat:
	go fmt ./...

.PHONY: test build release $(PLATFORMS) clean proto proto-builder reformat
