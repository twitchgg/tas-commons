package rpc

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/credentials"
	"ntsc.ac.cn/tas/tas-commons/pkg/secure"
)

// ServerConfig gRPC server config
type ServerConfig struct {
	TrustedCert      []byte
	ServerCert       []byte
	ServerPrivKey    []byte
	RequireAndVerify bool
	BindAddr         string
	// KStorageConf     *storage.KMCStorageConfig
}

// NewDefaultServerConfig create default gRPC server config
func NewDefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		BindAddr: "0.0.0.0:10001",
	}
}

// GetURL get rpc server listener url
func (conf *ServerConfig) GetURL() string {
	if conf.TrustedCert != nil ||
		conf.ServerCert != nil ||
		conf.ServerPrivKey != nil {
		if conf.RequireAndVerify {
			return "tcp+tls+verify://" + conf.BindAddr
		}
		return "tcp+tls://" + conf.BindAddr
	}
	return "tcp://" + conf.BindAddr
}

// Check check gRPC config
func (conf *ServerConfig) Check() (bool, error) {
	if _, err := net.ResolveTCPAddr("tcp", conf.BindAddr); err != nil {
		return false, fmt.Errorf("resolve gRPC server bind [%s] failed: %s",
			conf.BindAddr, err.Error())
	}
	if len(conf.TrustedCert) != 0 ||
		len(conf.ServerCert) != 0 ||
		len(conf.ServerPrivKey) != 0 {
		logrus.WithField("prefix", "common.rpc.config.check").
			Infof("using TLS checking")
		if conf.TrustedCert == nil || len(conf.TrustedCert) == 0 {
			return false, fmt.Errorf("gRPC config trusted certificate is not define")
		}
		if conf.ServerCert == nil || len(conf.ServerCert) == 0 {
			return false, fmt.Errorf("gRPC config server certificate is not define")
		}
		if conf.ServerPrivKey == nil || len(conf.ServerPrivKey) == 0 {
			return false, fmt.Errorf("gRPC config server private key is not define")
		}
		return true, nil
	}
	return false, nil
}

// NewTLSCreds create gRPC TLS credentials
func (conf *ServerConfig) NewTLSCreds() (credentials.TransportCredentials, error) {
	certificate, certPool, err := secure.NewTLSCerts(
		conf.TrustedCert, conf.ServerCert, conf.ServerPrivKey)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		MinVersion:               tls.VersionTLS11,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
	}
	if conf.RequireAndVerify {
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(tlsConf), nil
}
