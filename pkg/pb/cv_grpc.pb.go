// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.2
// source: pkg/proto/cv.proto

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

// CommonViewDataServiceClient is the client API for CommonViewDataService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CommonViewDataServiceClient interface {
	PushStationData(ctx context.Context, in *PushRequest, opts ...grpc.CallOption) (CommonViewDataService_PushStationDataClient, error)
	PullStationData(ctx context.Context, opts ...grpc.CallOption) (CommonViewDataService_PullStationDataClient, error)
}

type commonViewDataServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCommonViewDataServiceClient(cc grpc.ClientConnInterface) CommonViewDataServiceClient {
	return &commonViewDataServiceClient{cc}
}

func (c *commonViewDataServiceClient) PushStationData(ctx context.Context, in *PushRequest, opts ...grpc.CallOption) (CommonViewDataService_PushStationDataClient, error) {
	stream, err := c.cc.NewStream(ctx, &CommonViewDataService_ServiceDesc.Streams[0], "/CommonViewDataService/PushStationData", opts...)
	if err != nil {
		return nil, err
	}
	x := &commonViewDataServicePushStationDataClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type CommonViewDataService_PushStationDataClient interface {
	Recv() (*CommonViewRawData, error)
	grpc.ClientStream
}

type commonViewDataServicePushStationDataClient struct {
	grpc.ClientStream
}

func (x *commonViewDataServicePushStationDataClient) Recv() (*CommonViewRawData, error) {
	m := new(CommonViewRawData)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *commonViewDataServiceClient) PullStationData(ctx context.Context, opts ...grpc.CallOption) (CommonViewDataService_PullStationDataClient, error) {
	stream, err := c.cc.NewStream(ctx, &CommonViewDataService_ServiceDesc.Streams[1], "/CommonViewDataService/PullStationData", opts...)
	if err != nil {
		return nil, err
	}
	x := &commonViewDataServicePullStationDataClient{stream}
	return x, nil
}

type CommonViewDataService_PullStationDataClient interface {
	Send(*CommonViewRawData) error
	CloseAndRecv() (*PushRequest, error)
	grpc.ClientStream
}

type commonViewDataServicePullStationDataClient struct {
	grpc.ClientStream
}

func (x *commonViewDataServicePullStationDataClient) Send(m *CommonViewRawData) error {
	return x.ClientStream.SendMsg(m)
}

func (x *commonViewDataServicePullStationDataClient) CloseAndRecv() (*PushRequest, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(PushRequest)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// CommonViewDataServiceServer is the server API for CommonViewDataService service.
// All implementations should embed UnimplementedCommonViewDataServiceServer
// for forward compatibility
type CommonViewDataServiceServer interface {
	PushStationData(*PushRequest, CommonViewDataService_PushStationDataServer) error
	PullStationData(CommonViewDataService_PullStationDataServer) error
}

// UnimplementedCommonViewDataServiceServer should be embedded to have forward compatible implementations.
type UnimplementedCommonViewDataServiceServer struct {
}

func (UnimplementedCommonViewDataServiceServer) PushStationData(*PushRequest, CommonViewDataService_PushStationDataServer) error {
	return status.Errorf(codes.Unimplemented, "method PushStationData not implemented")
}
func (UnimplementedCommonViewDataServiceServer) PullStationData(CommonViewDataService_PullStationDataServer) error {
	return status.Errorf(codes.Unimplemented, "method PullStationData not implemented")
}

// UnsafeCommonViewDataServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CommonViewDataServiceServer will
// result in compilation errors.
type UnsafeCommonViewDataServiceServer interface {
	mustEmbedUnimplementedCommonViewDataServiceServer()
}

func RegisterCommonViewDataServiceServer(s grpc.ServiceRegistrar, srv CommonViewDataServiceServer) {
	s.RegisterService(&CommonViewDataService_ServiceDesc, srv)
}

func _CommonViewDataService_PushStationData_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(PushRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(CommonViewDataServiceServer).PushStationData(m, &commonViewDataServicePushStationDataServer{stream})
}

type CommonViewDataService_PushStationDataServer interface {
	Send(*CommonViewRawData) error
	grpc.ServerStream
}

type commonViewDataServicePushStationDataServer struct {
	grpc.ServerStream
}

func (x *commonViewDataServicePushStationDataServer) Send(m *CommonViewRawData) error {
	return x.ServerStream.SendMsg(m)
}

func _CommonViewDataService_PullStationData_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(CommonViewDataServiceServer).PullStationData(&commonViewDataServicePullStationDataServer{stream})
}

type CommonViewDataService_PullStationDataServer interface {
	SendAndClose(*PushRequest) error
	Recv() (*CommonViewRawData, error)
	grpc.ServerStream
}

type commonViewDataServicePullStationDataServer struct {
	grpc.ServerStream
}

func (x *commonViewDataServicePullStationDataServer) SendAndClose(m *PushRequest) error {
	return x.ServerStream.SendMsg(m)
}

func (x *commonViewDataServicePullStationDataServer) Recv() (*CommonViewRawData, error) {
	m := new(CommonViewRawData)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// CommonViewDataService_ServiceDesc is the grpc.ServiceDesc for CommonViewDataService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CommonViewDataService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "CommonViewDataService",
	HandlerType: (*CommonViewDataServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "PushStationData",
			Handler:       _CommonViewDataService_PushStationData_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "PullStationData",
			Handler:       _CommonViewDataService_PullStationData_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "pkg/proto/cv.proto",
}
