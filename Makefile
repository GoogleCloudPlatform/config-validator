PROTO_DOCKER_IMAGE=gcv-proto-builder

proto-builder:
	docker build -t $(PROTO_DOCKER_IMAGE) -f ./build/proto/Dockerfile .

proto: proto-builder
	docker run \
		-v `pwd`:/go/src/partner-code.googlesource.com/gcv/gcv \
		$(PROTO_DOCKER_IMAGE) \
		protoc -I/proto -I./api --go_out=plugins=grpc:./pkg/api/validator ./api/validator.proto

.PHONY: proto proto-builder
