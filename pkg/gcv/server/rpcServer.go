package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/golang/glog"
	"google.golang.org/grpc"
	"log"
	"net"
	"partner-code.googlesource.com/gcv/gcv/pkg/api/validator"
	"partner-code.googlesource.com/gcv/gcv/pkg/gcv"
)

var (
	policyPath = flag.String("policyPath", "", "directory containing policy templates and configs")
	// TODO(corb): Template development will eventually inline library code, but the currently template examples have dependency rego code.
	//  This flag will be deprecated when the template tooling is complete.
	policyLibraryPath = flag.String("policyLibraryPath", "", "directory containing policy templates and configs")
	port              = flag.Int("port", 10000, "The server port")
)

type gcvServer struct {
	validator *gcv.Validator
}

func (s *gcvServer) AddData(ctx context.Context, request *validator.AddDataRequest) (*validator.AddDataResponse, error) {
	err := s.validator.AddData(request)
	return &validator.AddDataResponse{}, err
}

func (s *gcvServer) Audit(ctx context.Context, request *validator.AuditRequest) (*validator.AuditResponse, error) {
	response, err := s.validator.Audit()
	return response, err
}

func (s *gcvServer) Reset(ctx context.Context, request *validator.ResetRequest) (*validator.ResetResponse, error) {
	err := s.validator.Reset()
	return &validator.ResetResponse{}, err
}

func newServer(policyPath, policyLibraryPath string) (*gcvServer, error) {
	s := &gcvServer{}
	v, err := gcv.NewValidator(gcv.PolicyPath(policyPath), gcv.PolicyLibraryDir(policyLibraryPath))
	if err != nil {
		return nil, err
	}
	s.validator = v
	return s, nil
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	grpcServer := grpc.NewServer()
	serverImpl, err := newServer(*policyPath, *policyLibraryPath)
	if err != nil {
		log.Fatalf("Failed to load server %v", err)
	}
	validator.RegisterValidatorServer(grpcServer, serverImpl)
	err = grpcServer.Serve(lis)
	if err != nil {
		glog.Fatalf("RPC server ungracefully stopped: %v", err)
	}
}
