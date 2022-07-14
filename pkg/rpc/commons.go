package rpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"ntsc.ac.cn/tas/tas-commons/pkg/secure"
)

const (
	CERT_EXT_KEY_MACHINE_ID = "1.1.1.1.1.1"
)

const (
	TRUSTED_CERT_CHAIN_NAME = "trusted.crt"
	CLIENT_CERT_NAME        = "client.crt"
	CLIENT_PRIVATE_KEY_NAME = "client.key"
	SERVER_CERT_NAME        = "server.crt"
	SERVER_PRIVATE_KEY_NAME = "server.key"
)

func CertCheckFunc(ctx context.Context) (context.Context, error) {
	pr, _ := peer.FromContext(ctx)
	logrus.WithField("prefix", "server").
		Debugf("client address: %s", pr.Addr.String())
	cert, err := GetClientCertificate(pr)
	if err != nil {
		return nil, err
	}
	logrus.WithField("prefix", "server").
		Debugf("client common name [%s],issuer common name[%s]",
			cert.Subject.CommonName, cert.Issuer.CommonName)
	return ctx, nil
}

func CheckMachineID(ctx context.Context, reqMachineID string) error {
	pr, _ := peer.FromContext(ctx)
	cert, err := GetClientCertificate(pr)
	if err != nil {
		return fmt.Errorf("get client certificate failed: %s", err.Error())
	}
	machineID, err := secure.GetCertExtValue(cert, CERT_EXT_KEY_MACHINE_ID)
	if err != nil {
		return GenerateError(codes.InvalidArgument,
			fmt.Errorf("not found machine id from certificate"))
	}
	if machineID != reqMachineID {
		return GenerateError(codes.InvalidArgument,
			fmt.Errorf("machine id does not match"))
	}
	return nil
}

func GetMachineID(ctx context.Context) (string, error) {
	pr, _ := peer.FromContext(ctx)
	cert, err := GetClientCertificate(pr)
	if err != nil {
		return "", fmt.Errorf(
			"get client certificate failed: %s", err.Error())
	}
	machineID, err := secure.GetCertExtValue(
		cert, CERT_EXT_KEY_MACHINE_ID)
	if err != nil {
		return "", GenerateError(codes.InvalidArgument,
			fmt.Errorf("not found machine id from certificate"))
	}
	return machineID, nil
}

// GetTlsConfig get grpc service tls config
func GetTlsConfig(machineID string, path string, servername string) (*tls.Config, error) {
	certPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate path failed: %v", err)
	}
	trustedPath := certPath + string(filepath.Separator) + TRUSTED_CERT_CHAIN_NAME
	clientCertPath := certPath + string(filepath.Separator) + CLIENT_CERT_NAME
	privKeyPath := certPath + string(filepath.Separator) + CLIENT_PRIVATE_KEY_NAME
	trusted, err := ioutil.ReadFile(trustedPath)
	if err != nil {
		return nil, fmt.Errorf(
			"read truested certificate chain failed: %v", err)
	}
	cert, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
		return nil, fmt.Errorf(
			"read client certificate failed: %v", err)
	}
	clientCert, err := secure.PEMToX509Certificate(cert)
	if err != nil {
		return nil, fmt.Errorf(
			"parse client certificate pem data failed: %v", err)
	}
	certMachineID, err := secure.GetCertExtValue(clientCert, CERT_EXT_KEY_MACHINE_ID)
	if err != nil {
		return nil, fmt.Errorf(
			"not found machine id from certificate")
	}
	if machineID != certMachineID {
		return nil, fmt.Errorf("machine id does not match")
	}
	privKey, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf(
			"read client certificate private key failed: %v", err)
	}
	tlsConf, err := NewClientTLSConfig(&ClientTLSConfig{
		CACert:     trusted,
		Cert:       cert,
		PrivKey:    privKey,
		ServerName: servername,
	})
	if err != nil {
		return nil, fmt.Errorf("generate tls config failed: %v", err)
	}
	return tlsConf, nil
}

// GenServerRPCConfig generate server config
func GenServerRPCConfig(path, listener string) (*ServerConfig, error) {
	trustedPath := path + string(filepath.Separator) + TRUSTED_CERT_CHAIN_NAME
	certPath := path + string(filepath.Separator) + SERVER_CERT_NAME
	privKeyPath := path + string(filepath.Separator) + SERVER_PRIVATE_KEY_NAME
	var trusted, cert, privKey []byte
	var err error
	if trusted, err = ioutil.ReadFile(trustedPath); err != nil {
		return nil, fmt.Errorf("read trusted certificate chain failed: %s", err.Error())
	}
	if cert, err = ioutil.ReadFile(certPath); err != nil {
		return nil, fmt.Errorf("read server certificate failed: %s", err.Error())
	}
	if privKey, err = ioutil.ReadFile(privKeyPath); err != nil {
		return nil, fmt.Errorf("read server private key failed: %s", err.Error())
	}
	uri, err := url.Parse(listener)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to parse listener [%s]: %v", listener, err)
	}
	return &ServerConfig{
		TrustedCert:      trusted,
		ServerCert:       cert,
		ServerPrivKey:    privKey,
		RequireAndVerify: true,
		BindAddr:         uri.Host,
	}, nil
}
