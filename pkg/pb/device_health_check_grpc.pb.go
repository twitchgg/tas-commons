// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.2
// source: pkg/proto/device_health_check.proto

package pb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// DeviceHealthClient is the client API for DeviceHealth service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type DeviceHealthClient interface {
	Watch(ctx context.Context, opts ...grpc.CallOption) (DeviceHealth_WatchClient, error)
}

type deviceHealthClient struct {
	cc grpc.ClientConnInterface
}

func NewDeviceHealthClient(cc grpc.ClientConnInterface) DeviceHealthClient {
	return &deviceHealthClient{cc}
}

func (c *deviceHealthClient) Watch(ctx context.Context, opts ...grpc.CallOption) (DeviceHealth_WatchClient, error) {
	stream, err := c.cc.NewStream(ctx, &DeviceHealth_ServiceDesc.Streams[0], "/DeviceHealth/Watch", opts...)
	if err != nil {
		return nil, err
	}
	x := &deviceHealthWatchClient{stream}
	return x, nil
}

type DeviceHealth_WatchClient interface {
	Send(*DeviceReportRequest) error
	CloseAndRecv() (*DeviceReportResponse, error)
	grpc.ClientStream
}

type deviceHealthWatchClient struct {
	grpc.ClientStream
}

func (x *deviceHealthWatchClient) Send(m *DeviceReportRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *deviceHealthWatchClient) CloseAndRecv() (*DeviceReportResponse, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(DeviceReportResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// DeviceHealthServer is the server API for DeviceHealth service.
// All implementations should embed UnimplementedDeviceHealthServer
// for forward compatibility
type DeviceHealthServer interface {
	Watch(DeviceHealth_WatchServer) error
}

// UnimplementedDeviceHealthServer should be embedded to have forward compatible implementations.
type UnimplementedDeviceHealthServer struct {
}

func (UnimplementedDeviceHealthServer) Watch(DeviceHealth_WatchServer) error {
	return status.Errorf(codes.Unimplemented, "method Watch not implemented")
}

// UnsafeDeviceHealthServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to DeviceHealthServer will
// result in compilation errors.
type UnsafeDeviceHealthServer interface {
	mustEmbedUnimplementedDeviceHealthServer()
}

func RegisterDeviceHealthServer(s grpc.ServiceRegistrar, srv DeviceHealthServer) {
	s.RegisterService(&DeviceHealth_ServiceDesc, srv)
}

func _DeviceHealth_Watch_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DeviceHealthServer).Watch(&deviceHealthWatchServer{stream})
}

type DeviceHealth_WatchServer interface {
	SendAndClose(*DeviceReportResponse) error
	Recv() (*DeviceReportRequest, error)
	grpc.ServerStream
}

type deviceHealthWatchServer struct {
	grpc.ServerStream
}

func (x *deviceHealthWatchServer) SendAndClose(m *DeviceReportResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *deviceHealthWatchServer) Recv() (*DeviceReportRequest, error) {
	m := new(DeviceReportRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// DeviceHealth_ServiceDesc is the grpc.ServiceDesc for DeviceHealth service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var DeviceHealth_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "DeviceHealth",
	HandlerType: (*DeviceHealthServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Watch",
			Handler:       _DeviceHealth_Watch_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "pkg/proto/device_health_check.proto",
}