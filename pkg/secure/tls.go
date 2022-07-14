package secure

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path/filepath"
)

// NewTLSCerts create TLS x509 certificates
func NewTLSCerts(certCA, cert, privKey []byte) (
	tls.Certificate, *x509.CertPool, error) {
	certificate, err := tls.X509KeyPair(cert, privKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPool, err := DecodeCertificateChainPool(certCA)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return certificate, certPool, nil
}

// NewTLSConfig create tls config
func NewTLSConfig(trusted, cert, privKey []byte, rav bool) (*tls.Config, error) {
	certificate, certPool, err := NewTLSCerts(
		trusted, cert, privKey)
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
	if rav {
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsConf, nil
}

type TLSType int

const (
	TLS_TYPE_SERVER TLSType = iota
	TLS_TYPE_CLIENT
)

// NewTLSConfigWithCertPath create tls config
func NewTLSConfigWithCertPath(rootPath string, tlsType TLSType, rav bool) (*tls.Config, error) {
	var certName string
	var keyName string
	switch tlsType {
	case TLS_TYPE_SERVER:
		certName = "server.crt"
		keyName = "server.key"
	case TLS_TYPE_CLIENT:
		certName = "client.crt"
		keyName = "client.key"
	}
	trustedPath := rootPath + string(filepath.Separator) + "trusted.crt"
	certPath := rootPath + string(filepath.Separator) + certName
	privKeyPath := rootPath + string(filepath.Separator) + keyName
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
	certificate, certPool, err := NewTLSCerts(
		trusted, cert, privKey)
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
	if rav {
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsConf, nil
}
