# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# NOTE: This Dockerfile is optimized for ease of changes (dev/release work)
# rather than number of layers.
FROM golang:1.20

RUN DEBIAN_FRONTEND=noninteractive apt update && \
    DEBIAN_FRONTEND=noninteractive apt install wget unzip python3-pip --assume-yes

ARG PROTOC_VERSION=3.6.1
RUN wget -q https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip && \
    unzip -d /usr/local protoc-${PROTOC_VERSION}-linux-x86_64.zip

RUN pip install grpcio-tools --break-system-packages

# Add a common directory for .proto includes
RUN mkdir /proto
RUN git clone https://github.com/googleapis/googleapis /tmp/googleapis

# Maintain expected import paths when using protoc -I/proto
RUN mv /tmp/googleapis/google /proto/google

WORKDIR /go/src/github.com/GoogleCloudPlatform/config-validator
COPY ./go.mod ./go.sum ./

ENV GO111MODULE=on
RUN go install github.com/golang/protobuf/protoc-gen-go

COPY ./api ./api
