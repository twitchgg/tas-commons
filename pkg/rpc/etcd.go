package rpc

import (
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	DefaultDialTimeout = time.Second * 3
)

type EtcdDiscovery struct {
	etcd *clientv3.Client
}

// NewEtcdDiscovery create ectd discovery
func NewEtcdDiscovery(endpoints ...string) (*EtcdDiscovery, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("discovery etcd endpoints not define")
	}
	config := clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: DefaultDialTimeout,
	}
	c, err := clientv3.New(config)
	if err != nil {
		return nil, err
	}
	return &EtcdDiscovery{
		etcd: c,
	}, nil
}
