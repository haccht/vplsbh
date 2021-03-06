// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.14.0
// source: bumstream.proto

package bumpb

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type Request struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Filter string `protobuf:"bytes,1,opt,name=filter,proto3" json:"filter,omitempty"`
	Domain string `protobuf:"bytes,2,opt,name=domain,proto3" json:"domain,omitempty"`
}

func (x *Request) Reset() {
	*x = Request{}
	if protoimpl.UnsafeEnabled {
		mi := &file_bumstream_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Request) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Request) ProtoMessage() {}

func (x *Request) ProtoReflect() protoreflect.Message {
	mi := &file_bumstream_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Request.ProtoReflect.Descriptor instead.
func (*Request) Descriptor() ([]byte, []int) {
	return file_bumstream_proto_rawDescGZIP(), []int{0}
}

func (x *Request) GetFilter() string {
	if x != nil {
		return x.Filter
	}
	return ""
}

func (x *Request) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

type Packet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Data      []byte                 `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
	Label     uint32                 `protobuf:"varint,2,opt,name=label,proto3" json:"label,omitempty"`
	Remote    string                 `protobuf:"bytes,3,opt,name=remote,proto3" json:"remote,omitempty"`
	Domain    string                 `protobuf:"bytes,4,opt,name=domain,proto3" json:"domain,omitempty"`
	Timestamp *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
}

func (x *Packet) Reset() {
	*x = Packet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_bumstream_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Packet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Packet) ProtoMessage() {}

func (x *Packet) ProtoReflect() protoreflect.Message {
	mi := &file_bumstream_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Packet.ProtoReflect.Descriptor instead.
func (*Packet) Descriptor() ([]byte, []int) {
	return file_bumstream_proto_rawDescGZIP(), []int{1}
}

func (x *Packet) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *Packet) GetLabel() uint32 {
	if x != nil {
		return x.Label
	}
	return 0
}

func (x *Packet) GetRemote() string {
	if x != nil {
		return x.Remote
	}
	return ""
}

func (x *Packet) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

func (x *Packet) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

var File_bumstream_proto protoreflect.FileDescriptor

var file_bumstream_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x62, 0x75, 0x6d, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x1a, 0x1f, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x39, 0x0a, 0x07,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x66, 0x69, 0x6c, 0x74, 0x65,
	0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x12,
	0x16, 0x0a, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x22, 0x9c, 0x01, 0x0a, 0x06, 0x50, 0x61, 0x63, 0x6b,
	0x65, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x12, 0x16, 0x0a, 0x06,
	0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x65,
	0x6d, 0x6f, 0x74, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x38, 0x0a, 0x09,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x32, 0x43, 0x0a, 0x0f, 0x42, 0x75, 0x6d, 0x53, 0x6e, 0x69,
	0x66, 0x66, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x30, 0x0a, 0x05, 0x53, 0x6e, 0x69,
	0x66, 0x66, 0x12, 0x11, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x10, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x22, 0x00, 0x30, 0x01, 0x42, 0x09, 0x5a, 0x07, 0x2e,
	0x3b, 0x62, 0x75, 0x6d, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_bumstream_proto_rawDescOnce sync.Once
	file_bumstream_proto_rawDescData = file_bumstream_proto_rawDesc
)

func file_bumstream_proto_rawDescGZIP() []byte {
	file_bumstream_proto_rawDescOnce.Do(func() {
		file_bumstream_proto_rawDescData = protoimpl.X.CompressGZIP(file_bumstream_proto_rawDescData)
	})
	return file_bumstream_proto_rawDescData
}

var file_bumstream_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_bumstream_proto_goTypes = []interface{}{
	(*Request)(nil),               // 0: protobuf.Request
	(*Packet)(nil),                // 1: protobuf.Packet
	(*timestamppb.Timestamp)(nil), // 2: google.protobuf.Timestamp
}
var file_bumstream_proto_depIdxs = []int32{
	2, // 0: protobuf.Packet.timestamp:type_name -> google.protobuf.Timestamp
	0, // 1: protobuf.BumSniffService.Sniff:input_type -> protobuf.Request
	1, // 2: protobuf.BumSniffService.Sniff:output_type -> protobuf.Packet
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_bumstream_proto_init() }
func file_bumstream_proto_init() {
	if File_bumstream_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_bumstream_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Request); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_bumstream_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Packet); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_bumstream_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_bumstream_proto_goTypes,
		DependencyIndexes: file_bumstream_proto_depIdxs,
		MessageInfos:      file_bumstream_proto_msgTypes,
	}.Build()
	File_bumstream_proto = out.File
	file_bumstream_proto_rawDesc = nil
	file_bumstream_proto_goTypes = nil
	file_bumstream_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// BumSniffServiceClient is the client API for BumSniffService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type BumSniffServiceClient interface {
	Sniff(ctx context.Context, in *Request, opts ...grpc.CallOption) (BumSniffService_SniffClient, error)
}

type bumSniffServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewBumSniffServiceClient(cc grpc.ClientConnInterface) BumSniffServiceClient {
	return &bumSniffServiceClient{cc}
}

func (c *bumSniffServiceClient) Sniff(ctx context.Context, in *Request, opts ...grpc.CallOption) (BumSniffService_SniffClient, error) {
	stream, err := c.cc.NewStream(ctx, &_BumSniffService_serviceDesc.Streams[0], "/protobuf.BumSniffService/Sniff", opts...)
	if err != nil {
		return nil, err
	}
	x := &bumSniffServiceSniffClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type BumSniffService_SniffClient interface {
	Recv() (*Packet, error)
	grpc.ClientStream
}

type bumSniffServiceSniffClient struct {
	grpc.ClientStream
}

func (x *bumSniffServiceSniffClient) Recv() (*Packet, error) {
	m := new(Packet)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// BumSniffServiceServer is the server API for BumSniffService service.
type BumSniffServiceServer interface {
	Sniff(*Request, BumSniffService_SniffServer) error
}

// UnimplementedBumSniffServiceServer can be embedded to have forward compatible implementations.
type UnimplementedBumSniffServiceServer struct {
}

func (*UnimplementedBumSniffServiceServer) Sniff(*Request, BumSniffService_SniffServer) error {
	return status.Errorf(codes.Unimplemented, "method Sniff not implemented")
}

func RegisterBumSniffServiceServer(s *grpc.Server, srv BumSniffServiceServer) {
	s.RegisterService(&_BumSniffService_serviceDesc, srv)
}

func _BumSniffService_Sniff_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Request)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(BumSniffServiceServer).Sniff(m, &bumSniffServiceSniffServer{stream})
}

type BumSniffService_SniffServer interface {
	Send(*Packet) error
	grpc.ServerStream
}

type bumSniffServiceSniffServer struct {
	grpc.ServerStream
}

func (x *bumSniffServiceSniffServer) Send(m *Packet) error {
	return x.ServerStream.SendMsg(m)
}

var _BumSniffService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "protobuf.BumSniffService",
	HandlerType: (*BumSniffServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Sniff",
			Handler:       _BumSniffService_Sniff_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "bumstream.proto",
}
