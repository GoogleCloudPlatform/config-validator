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

.PHONY: test
test:
	GO111MODULE=on go test ./...

.PHONY: build
build: format proto

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
