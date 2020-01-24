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

# Build policy-tool
FROM golang:1.13.6 as build

WORKDIR /go/src/app

# Cache go module download (only re-runs this when mod / sum changes)
ENV GO111MODULE=on
COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

RUN make policy-tool-linux

# Now copy it into our static image.
FROM gcr.io/distroless/static:nonroot as runtime
WORKDIR /mnt
COPY --chown=nonroot:nonroot --from=build /go/src/app/bin/policy-tool-linux-amd64 /policy-tool
ENTRYPOINT ["/policy-tool"]
