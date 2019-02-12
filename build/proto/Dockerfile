FROM golang:1.11

RUN apt-get update && apt-get -y install wget unzip
RUN wget https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protoc-3.6.1-linux-x86_64.zip && \
    unzip -d /usr/local protoc-3.6.1-linux-x86_64.zip

WORKDIR /go/src/partner-code.googlesource.com/gcv/gcv
COPY ./go.mod ./go.sum ./
COPY ./api ./api

ENV GO111MODULE=on
RUN go install github.com/golang/protobuf/protoc-gen-go
