package rpc

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var kaep = keepalive.EnforcementPolicy{
	MinTime:             5 * time.Second,
	PermitWithoutStream: true,
}

var kasp = keepalive.ServerParameters{
	MaxConnectionIdle: 15 * time.Second,
	// MaxConnectionAge:      30 * time.Second,
	MaxConnectionAgeGrace: 5 * time.Second,
	Time:                  5 * time.Second,
	Timeout:               2 * time.Second,
}

// Server gRPC server
type Server struct {
	rpcServ *grpc.Server
	conf    *ServerConfig
}

// NewServer create gRPC server with server config
func NewServer(conf *ServerConfig, opts []grpc.ServerOption,
	registry func(*grpc.Server)) (*Server, error) {
	if conf == nil {
		return nil, fmt.Errorf("rpc server config is not define")
	}
	if opts == nil {
		opts = []grpc.ServerOption{}
	}
	opts = append(opts, []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(kaep),
		grpc.KeepaliveParams(kasp),
	}...,
	)
	if isTLS, err := conf.Check(); err != nil {
		return nil, fmt.Errorf("check rpc server config error: %s", err.Error())
	} else if isTLS {
		creds, err := conf.NewTLSCreds()
		if err != nil {
			return nil,
				fmt.Errorf("create gRPC server tls credentials error:%s", err.Error())
		}
		logrus.WithField("prefix", "common.rpc.new").
			Infof("start gRPC server with tls,client verify require [%v]", conf.RequireAndVerify)
		opts = append(opts, grpc.Creds(creds))
	}
	rpcServ := grpc.NewServer(opts...)
	if registry == nil {
		return nil,
			fmt.Errorf("rpc server registry function is not define")
	}
	registry(rpcServ)
	return &Server{
		rpcServ: rpcServ,
		conf:    conf,
	}, nil
}

// NewDefaultServer create gRPC server with default server config
func NewDefaultServer(registry func(*grpc.Server)) (*Server, error) {
	conf := NewDefaultServerConfig()
	return NewServer(conf, nil, registry)
}

// Start start gRPC server with background
func (s *Server) Start() chan error {
	var errChan chan error
	lis, err := net.Listen("tcp", s.conf.BindAddr)
	if err != nil {
		errChan <- err
		return errChan
	}
	if s.conf.BindAddr == "" {
		lisPort := lis.Addr().(*net.TCPAddr).Port
		s.conf.BindAddr = "0.0.0.0:" + strconv.Itoa(lisPort)
	}

	logrus.WithField("prefix", "common.rpc.start").
		Infof("start gRPC server with bind address [%s]", s.conf.BindAddr)
	go func() {
		errChan <- s.rpcServ.Serve(lis)
	}()
	return errChan
}

// Close close gRPC server
func (s *Server) Close() error {
	s.rpcServ.Stop()
	return nil
}

// GetListenerAddr get server listener address
func (s *Server) GetListenerAddr() string {
	return s.conf.GetURL()
}

func (s *Server) IsSSL() bool {
	return len(s.conf.TrustedCert) != 0
}

// GetClientAddr get client address
func GetClientAddr(ctx context.Context) (net.Addr, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("get client ip error")
	} else if p.Addr == net.Addr(nil) {
		return nil, fmt.Errorf("client ip is nil")
	}
	return p.Addr, nil
}

// GenerateArgumentRequiredError generate rpc invalid argument error
func GenerateArgumentRequiredError(name string) error {
	err := status.Errorf(codes.InvalidArgument, name+" is required")
	return err
}

// GenerateArgumentError generate rpc invalid argument error
func GenerateArgumentError(desc string) error {
	err := status.Errorf(codes.InvalidArgument, desc)
	return err
}

// GenerateError generate rpc invalid argument error
func GenerateError(code codes.Code, err error) error {
	aerr := status.Errorf(code, err.Error())
	return aerr
}

// GetClientCertificate get client certificate
func GetClientCertificate(pr *peer.Peer) (*x509.Certificate, error) {
	if pr == nil {
		return nil, fmt.Errorf("peer is nil")
	}
	switch info := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		if len(info.State.PeerCertificates) == 0 {
			return nil, status.Error(codes.Unauthenticated, "no certificate")
		}
		return info.State.PeerCertificates[0], nil
	default:
		return nil, status.Error(codes.Unauthenticated, "Unknown AuthInfo type")
	}
}
