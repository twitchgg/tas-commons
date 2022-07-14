package rpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"ntsc.ac.cn/tas/tas-commons/pkg/secure"
)

var kacp = keepalive.ClientParameters{
	Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
	Timeout:             time.Second * 2,  // wait 1 second for ping ack before considering the connection dead
	PermitWithoutStream: true,             // send pings even without active streams
}

// ClientConn gRPC client connection
type ClientConn struct {
	conn net.Conn
}

// DialOptions dial options
type DialOptions struct {
	RemoteAddr string
	TLSConfig  *tls.Config
}

// NewClientConn create gRPC client connection
func NewClientConn(conn net.Conn) *ClientConn {
	return &ClientConn{conn: conn}
}

// DialRPCConn dial gRPC client connection
func DialRPCConn(dialOpts *DialOptions) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithKeepaliveParams(kacp),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, remote string) (net.Conn, error) {
			info, err := url.Parse(remote)
			if err != nil {
				return nil, fmt.Errorf("parse remote addr [%s] error: %s", remote, err.Error())
			}
			if info.Scheme == "tcp+tls+verify" {
				if dialOpts.TLSConfig == nil {
					return nil, fmt.Errorf("server scheme is [tcp+tls+verify],tls config requierd")
				}
				if dialOpts.TLSConfig.Certificates == nil ||
					len(dialOpts.TLSConfig.Certificates) == 0 {
					return nil, fmt.Errorf(
						"server scheme is [tcp+tls+verify],client certificates requierd")
				}
			}
			return dialConn(ctx, &DialOptions{
				RemoteAddr: remote,
				TLSConfig:  dialOpts.TLSConfig,
			})
		}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	return grpc.DialContext(ctx, dialOpts.RemoteAddr, opts...)
}

func dialConn(ctx context.Context, opts *DialOptions) (*ClientConn, error) {
	info, err := url.Parse(opts.RemoteAddr)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	d.Timeout = time.Second * 3
	host := info.Hostname() + ":" + info.Port()
	var nc net.Conn

	if opts.TLSConfig != nil {
		nc, err = tls.DialWithDialer(&d, info.Scheme, host, opts.TLSConfig)
	} else {
		nc, err = d.DialContext(ctx, info.Scheme, host)
	}
	if err != nil {
		return nil, err
	}
	return &ClientConn{conn: nc}, err
}

// Read reads data from the connection.
func (c *ClientConn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

// Write writes data to the connection.
func (c *ClientConn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

// Close closes the connection.
func (c *ClientConn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *ClientConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *ClientConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
func (c *ClientConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
func (c *ClientConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
func (c *ClientConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// ClientTLSConfig client tls config
type ClientTLSConfig struct {
	CACert             []byte
	Cert               []byte
	PrivKey            []byte
	InsecureSkipVerify bool
	ServerName         string
}

// NewClientTLSConfig create client tls config
func NewClientTLSConfig(conf *ClientTLSConfig) (
	*tls.Config, error) {
	if conf.CACert == nil {
		return &tls.Config{
			InsecureSkipVerify: true,
		}, nil
	}
	certificate, certPool, err := secure.NewTLSCerts(
		conf.CACert, conf.Cert, conf.PrivKey)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		RootCAs:            certPool,
		ClientCAs:          certPool,
		InsecureSkipVerify: conf.InsecureSkipVerify,
		ServerName:         conf.ServerName,
		MinVersion:         tls.VersionTLS11,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
	}
	return tlsConf, nil
}
