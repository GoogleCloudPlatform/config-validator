// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/forseti-security/config-validator/pkg/api/validator"
	"github.com/forseti-security/config-validator/pkg/gcv"
	"github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	policyPath = flag.String("policyPath", "", "directory containing policy templates and configs")
	// TODO(corb): Template development will eventually inline library code, but the currently template examples have dependency rego code.
	//  This flag will be deprecated when the template tooling is complete.
	policyLibraryPath  = flag.String("policyLibraryPath", "", "directory containing policy templates and configs")
	port               = flag.Int("port", 10000, "The server port")
	maxMessageRecvSize = flag.Int(
		"maxMessageRecvSize", 128*1024*1024, "The max message receive size for the RPC service")
)

type gcvServer struct {
	validator *gcv.Validator
}

func (s *gcvServer) AddData(ctx context.Context, request *validator.AddDataRequest) (*validator.AddDataResponse, error) {
	err := s.validator.AddData(request)
	if err != nil {
		return &validator.AddDataResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &validator.AddDataResponse{}, nil
}

func (s *gcvServer) Audit(ctx context.Context, request *validator.AuditRequest) (*validator.AuditResponse, error) {
	resp, err := s.validator.Audit(ctx)
	if err != nil {
		return resp, status.Error(codes.Internal, err.Error())
	}
	return resp, nil
}

func (s *gcvServer) Reset(ctx context.Context, request *validator.ResetRequest) (*validator.ResetResponse, error) {
	err := s.validator.Reset(ctx)
	if err != nil {
		return &validator.ResetResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &validator.ResetResponse{}, nil
}

func (s *gcvServer) Review(ctx context.Context, request *validator.ReviewRequest) (*validator.ReviewResponse, error) {
	return s.validator.Review(ctx, request)
}

func newServer(stopChannel chan struct{}, policyPath, policyLibraryPath string) (*gcvServer, error) {
	v, err := gcv.NewValidator(stopChannel, policyPath, policyLibraryPath)
	if err != nil {
		return nil, err
	}
	return &gcvServer{
		validator: v,
	}, nil
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}

	stopChannel := make(chan struct{})
	defer close(stopChannel)
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(*maxMessageRecvSize),
	)
	serverImpl, err := newServer(stopChannel, *policyPath, *policyLibraryPath)
	if err != nil {
		log.Fatalf("Failed to load server %v", err)
	}
	validator.RegisterValidatorServer(grpcServer, serverImpl)
	if err := grpcServer.Serve(lis); err != nil {
		glog.Fatalf("RPC server ungracefully stopped: %v", err)
	}
}
