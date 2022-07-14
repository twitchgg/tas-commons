package secure

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
)

// CriticalTimestampingExtension timestamp extension
func CriticalTimestampingExtension() (ext pkix.Extension, err error) {
	var oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	var oidExtKeyUsageTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}

	ext = pkix.Extension{}
	ext.Id = oidExtensionExtendedKeyUsage
	ext.Critical = true
	ext.Value, err = asn1.Marshal([]asn1.ObjectIdentifier{oidExtKeyUsageTimeStamping})
	return ext, err
}

// GenerateCertificate generate certificate
func GenerateCertificate(csr *x509.CertificateRequest, isCA bool, days uint32,
	serialNumber *big.Int,
	signCert *x509.Certificate, signPrivKey interface{},
	keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage,
	pathlen int) (*x509.Certificate, error) {
	notBefore := time.Now().UTC()
	td := time.Duration(int64(time.Hour) * int64(24*days))
	notAfter := notBefore.Add(td).UTC()
	keyID, err := genSubjectID()
	if err != nil {
		return nil, err
	}
	certTemplate := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		ExtraExtensions:       csr.Extensions,
		SubjectKeyId:          keyID,
		AuthorityKeyId:        keyID,
		SignatureAlgorithm:    csr.SignatureAlgorithm,
		KeyUsage:              keyUsage,
		Extensions:            csr.Extensions,
		ExtKeyUsage:           extKeyUsage,
	}
	if pathlen > 0 {
		certTemplate.MaxPathLen = pathlen
	}
	if signCert != nil {
		certTemplate.AuthorityKeyId = signCert.SubjectKeyId
	}
	isTs := false
	for _, u := range extKeyUsage {
		if u == x509.ExtKeyUsageTimeStamping {
			isTs = true
		}
	}
	if isTs {
		certTemplate.IsCA = false
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
		criticalTimestampExt, err := CriticalTimestampingExtension()
		if err != nil {
			return nil, err
		}
		certTemplate.ExtraExtensions = append([]pkix.Extension{criticalTimestampExt},
			certTemplate.ExtraExtensions...)
	}
	if signCert == nil {
		signCert = &certTemplate
	}
	certBytes, err := x509.CreateCertificate(
		rand.Reader, &certTemplate, signCert, csr.PublicKey, signPrivKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certBytes)
}

func genSubjectID() ([]byte, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	idBytes, err := id.MarshalText()
	if err != nil {
		return nil, err
	}
	hasher := md5.New()
	hasher.Write(idBytes)
	return hasher.Sum(nil), nil
}

// X509CertificateToPEM x509 certificate format to PEM
func X509CertificateToPEM(cert *x509.Certificate) ([]byte, error) {
	return DataToPEM(cert.Raw, "CERTIFICATE")
}

// PEMToX509CertificateRequest pem data to x509 certificate request
func PEMToX509CertificateRequest(pemData []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// PEMToX509Certificate pem data to x509 certificate request
func PEMToX509Certificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	return x509.ParseCertificate(block.Bytes)
}

// DecodeCertificateChain decode certificate chain
func DecodeCertificateChain(certPEMBlock []byte) tls.Certificate {
	var cert tls.Certificate
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}
	return cert
}

// DecodeCertificateChainPool decode certificate chain pool
func DecodeCertificateChainPool(certPEMBlock []byte) (*x509.CertPool, error) {
	chainCert := DecodeCertificateChain(certPEMBlock)
	return DecodeCertificateChainPoolWithTLSCerts(chainCert)
}

// DecodeCertificateChainPoolWithTLSCerts decode certificate chain pool
func DecodeCertificateChainPoolWithTLSCerts(chainCert tls.Certificate) (*x509.CertPool, error) {
	trustedPool := x509.NewCertPool()
	for _, cc := range chainCert.Certificate {
		x509Cert, err := x509.ParseCertificate(cc)
		if err != nil {
			return nil, err
		}
		trustedPool.AddCert(x509Cert)
	}
	return trustedPool, nil
}

// ConvertTLSCertificates convert TLS certificates to x509 certificates
func ConvertTLSCertificates(certPEMBlock []byte) ([]*x509.Certificate, error) {
	chainCert := DecodeCertificateChain(certPEMBlock)
	var x509Certs []*x509.Certificate
	for _, cc := range chainCert.Certificate {
		x509Cert, err := x509.ParseCertificate(cc)
		if err != nil {
			return nil, err
		}
		x509Certs = append(x509Certs, x509Cert)
	}
	return x509Certs, nil
}

// CreateGenericCRL is a helper function that takes in all of the information above, and then calls the createCRL
// function. This outputs the bytes of the created CRL.
func CreateGenericCRL(certList []pkix.RevokedCertificate, key crypto.Signer,
	issuingCert *x509.Certificate, expiryTime time.Time) ([]byte, error) {
	crlBytes, err := issuingCert.CreateCRL(
		rand.Reader, key, certList, time.Now(), expiryTime)
	if err != nil {
		return nil, err
	}
	return crlBytes, err
}

// DataToPEM generate pem string
func DataToPEM(data []byte, name string) ([]byte, error) {
	var printBuf bytes.Buffer
	if err := pem.Encode(&printBuf,
		&pem.Block{Type: name, Bytes: data}); err != nil {
		return nil, err
	}
	return printBuf.Bytes(), nil
}

// GetCertExtValue get certificate extension value
func GetCertExtValue(cert *x509.Certificate, key string) (string, error) {
	for _, v := range cert.Extensions {
		if v.Id.String() == key {
			return string(v.Value), nil
		}
	}
	return "", fmt.Errorf("not found extension [%s]", key)
}
