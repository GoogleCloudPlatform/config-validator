// Code generated by protoc-gen-go. DO NOT EDIT.
// source: validator.proto

package validator

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/golang/protobuf/ptypes/empty"
import _struct "github.com/golang/protobuf/ptypes/struct"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Asset contains GCP resource metadata and additional metadata set on a resource, such as Cloud IAM policy.
type Asset struct {
	// GCP resource name as defined by Cloud Asset Inventory.
	// See https://cloud.google.com/resource-manager/docs/cloud-asset-inventory/resource-name-format for the format.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Cloud Asset Inventory type. Example: "google.cloud.sql.Instance" is the type of Cloud SQL instance.
	// This field has a redundant "asset" prefix to be consistent with Cloud Asset Inventory output.
	// See https://cloud.google.com/resource-manager/docs/cloud-asset-inventory/overview#supported_resource_types for the list of types.
	AssetType string `protobuf:"bytes,2,opt,name=asset_type,json=assetType,proto3" json:"asset_type,omitempty"`
	// Ancestral project/folder/org information in a path-like format.
	// For example, a GCP project that is nested under a folder may have the following path:
	// organization/9999/folders/8888/projects/7777
	AncestryPath string `protobuf:"bytes,3,opt,name=ancestry_path,json=ancestryPath,proto3" json:"ancestry_path,omitempty"`
	// GCP resource metadata. The schema is type dependent.
	Resource             *_struct.Value `protobuf:"bytes,4,opt,name=resource,proto3" json:"resource,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *Asset) Reset()         { *m = Asset{} }
func (m *Asset) String() string { return proto.CompactTextString(m) }
func (*Asset) ProtoMessage()    {}
func (*Asset) Descriptor() ([]byte, []int) {
	return fileDescriptor_validator_82128c9b1f9bbc34, []int{0}
}
func (m *Asset) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Asset.Unmarshal(m, b)
}
func (m *Asset) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Asset.Marshal(b, m, deterministic)
}
func (dst *Asset) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Asset.Merge(dst, src)
}
func (m *Asset) XXX_Size() int {
	return xxx_messageInfo_Asset.Size(m)
}
func (m *Asset) XXX_DiscardUnknown() {
	xxx_messageInfo_Asset.DiscardUnknown(m)
}

var xxx_messageInfo_Asset proto.InternalMessageInfo

func (m *Asset) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Asset) GetAssetType() string {
	if m != nil {
		return m.AssetType
	}
	return ""
}

func (m *Asset) GetAncestryPath() string {
	if m != nil {
		return m.AncestryPath
	}
	return ""
}

func (m *Asset) GetResource() *_struct.Value {
	if m != nil {
		return m.Resource
	}
	return nil
}

// Violation contains the relevant information to explain how a constraint is violated.
type Violation struct {
	// The name of the constraint that's violated.
	Constraint string `protobuf:"bytes,1,opt,name=constraint,proto3" json:"constraint,omitempty"`
	// GCP resource name. This is the same name in Asset.
	Resource string `protobuf:"bytes,2,opt,name=resource,proto3" json:"resource,omitempty"`
	// Human readable error message.
	Message string `protobuf:"bytes,3,opt,name=message,proto3" json:"message,omitempty"`
	// Metadata is optional. It contains the constraint-specific information that can potentially be used for remediation.
	// Example: In a firewall rule constraint violation, Metadata can contain the open port number.
	Metadata             *_struct.Value `protobuf:"bytes,4,opt,name=metadata,proto3" json:"metadata,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *Violation) Reset()         { *m = Violation{} }
func (m *Violation) String() string { return proto.CompactTextString(m) }
func (*Violation) ProtoMessage()    {}
func (*Violation) Descriptor() ([]byte, []int) {
	return fileDescriptor_validator_82128c9b1f9bbc34, []int{1}
}
func (m *Violation) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Violation.Unmarshal(m, b)
}
func (m *Violation) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Violation.Marshal(b, m, deterministic)
}
func (dst *Violation) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Violation.Merge(dst, src)
}
func (m *Violation) XXX_Size() int {
	return xxx_messageInfo_Violation.Size(m)
}
func (m *Violation) XXX_DiscardUnknown() {
	xxx_messageInfo_Violation.DiscardUnknown(m)
}

var xxx_messageInfo_Violation proto.InternalMessageInfo

func (m *Violation) GetConstraint() string {
	if m != nil {
		return m.Constraint
	}
	return ""
}

func (m *Violation) GetResource() string {
	if m != nil {
		return m.Resource
	}
	return ""
}

func (m *Violation) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func (m *Violation) GetMetadata() *_struct.Value {
	if m != nil {
		return m.Metadata
	}
	return nil
}

type AddDataRequest struct {
	Assets               []*Asset `protobuf:"bytes,1,rep,name=assets,proto3" json:"assets,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AddDataRequest) Reset()         { *m = AddDataRequest{} }
func (m *AddDataRequest) String() string { return proto.CompactTextString(m) }
func (*AddDataRequest) ProtoMessage()    {}
func (*AddDataRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_validator_82128c9b1f9bbc34, []int{2}
}
func (m *AddDataRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AddDataRequest.Unmarshal(m, b)
}
func (m *AddDataRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AddDataRequest.Marshal(b, m, deterministic)
}
func (dst *AddDataRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AddDataRequest.Merge(dst, src)
}
func (m *AddDataRequest) XXX_Size() int {
	return xxx_messageInfo_AddDataRequest.Size(m)
}
func (m *AddDataRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AddDataRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AddDataRequest proto.InternalMessageInfo

func (m *AddDataRequest) GetAssets() []*Asset {
	if m != nil {
		return m.Assets
	}
	return nil
}

type AuditResponse struct {
	Violations           []*Violation `protobuf:"bytes,1,rep,name=violations,proto3" json:"violations,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *AuditResponse) Reset()         { *m = AuditResponse{} }
func (m *AuditResponse) String() string { return proto.CompactTextString(m) }
func (*AuditResponse) ProtoMessage()    {}
func (*AuditResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_validator_82128c9b1f9bbc34, []int{3}
}
func (m *AuditResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AuditResponse.Unmarshal(m, b)
}
func (m *AuditResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AuditResponse.Marshal(b, m, deterministic)
}
func (dst *AuditResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuditResponse.Merge(dst, src)
}
func (m *AuditResponse) XXX_Size() int {
	return xxx_messageInfo_AuditResponse.Size(m)
}
func (m *AuditResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_AuditResponse.DiscardUnknown(m)
}

var xxx_messageInfo_AuditResponse proto.InternalMessageInfo

func (m *AuditResponse) GetViolations() []*Violation {
	if m != nil {
		return m.Violations
	}
	return nil
}

func init() {
	proto.RegisterType((*Asset)(nil), "validator.Asset")
	proto.RegisterType((*Violation)(nil), "validator.Violation")
	proto.RegisterType((*AddDataRequest)(nil), "validator.AddDataRequest")
	proto.RegisterType((*AuditResponse)(nil), "validator.AuditResponse")
}

func init() { proto.RegisterFile("validator.proto", fileDescriptor_validator_82128c9b1f9bbc34) }

var fileDescriptor_validator_82128c9b1f9bbc34 = []byte{
	// 373 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0x4f, 0xcb, 0xd3, 0x40,
	0x10, 0xc6, 0xdf, 0xf8, 0xbe, 0x6d, 0xcd, 0xd4, 0xaa, 0x0c, 0x22, 0x31, 0xfe, 0xa1, 0xc4, 0x4b,
	0x4e, 0x29, 0x44, 0x2f, 0x2a, 0x08, 0x05, 0x7b, 0x97, 0x20, 0xbd, 0x96, 0x69, 0x32, 0xb6, 0x81,
	0x24, 0x1b, 0xb3, 0x93, 0x42, 0x3e, 0x87, 0xf8, 0x89, 0xfc, 0x62, 0x92, 0xcd, 0x1f, 0xa3, 0x52,
	0xbc, 0x65, 0x9f, 0xe7, 0x99, 0xcc, 0x6f, 0x67, 0x07, 0x1e, 0x5d, 0x28, 0x4b, 0x13, 0x12, 0x55,
	0x05, 0x65, 0xa5, 0x44, 0xa1, 0x3d, 0x0a, 0xee, 0xf3, 0x93, 0x52, 0xa7, 0x8c, 0x37, 0xc6, 0x38,
	0xd6, 0x5f, 0x37, 0x9c, 0x97, 0xd2, 0x74, 0x39, 0xf7, 0xc5, 0xdf, 0xa6, 0x96, 0xaa, 0x8e, 0xa5,
	0x73, 0xbd, 0xef, 0x16, 0xcc, 0xb6, 0x5a, 0xb3, 0x20, 0xc2, 0x5d, 0x41, 0x39, 0x3b, 0xd6, 0xda,
	0xf2, 0xed, 0xc8, 0x7c, 0xe3, 0x4b, 0x00, 0x6a, 0xcd, 0x83, 0x34, 0x25, 0x3b, 0xf7, 0x8c, 0x63,
	0x1b, 0xe5, 0x4b, 0x53, 0x32, 0xbe, 0x86, 0x15, 0x15, 0x31, 0x6b, 0xa9, 0x9a, 0x43, 0x49, 0x72,
	0x76, 0x6e, 0x4d, 0xe2, 0xc1, 0x20, 0x7e, 0x26, 0x39, 0x63, 0x08, 0xf7, 0x2b, 0xd6, 0xaa, 0xae,
	0x62, 0x76, 0xee, 0xd6, 0x96, 0xbf, 0x0c, 0x9f, 0x06, 0x1d, 0x52, 0x30, 0x20, 0x05, 0x7b, 0xca,
	0x6a, 0x8e, 0xc6, 0x9c, 0xf7, 0xc3, 0x02, 0x7b, 0x9f, 0xaa, 0x8c, 0x24, 0x55, 0x05, 0xbe, 0x02,
	0x88, 0x55, 0xa1, 0xa5, 0xa2, 0xb4, 0x90, 0x9e, 0x6f, 0xa2, 0xa0, 0x3b, 0xe9, 0xd0, 0x31, 0x8e,
	0x67, 0x74, 0x60, 0x91, 0xb3, 0xd6, 0x74, 0xe2, 0x1e, 0x6e, 0x38, 0xb6, 0x5c, 0x39, 0x0b, 0x25,
	0x24, 0xf4, 0x3f, 0xae, 0x21, 0xe7, 0xbd, 0x87, 0x87, 0xdb, 0x24, 0xf9, 0x44, 0x42, 0x11, 0x7f,
	0xab, 0x59, 0x0b, 0xfa, 0x30, 0x37, 0xf3, 0xd0, 0x8e, 0xb5, 0xbe, 0xf5, 0x97, 0xe1, 0xe3, 0xe0,
	0xf7, 0x3b, 0x99, 0xb9, 0x46, 0xbd, 0xef, 0xed, 0x60, 0xb5, 0xad, 0x93, 0x54, 0x22, 0xd6, 0xa5,
	0x2a, 0x34, 0xe3, 0x5b, 0x80, 0xcb, 0x70, 0xc7, 0xa1, 0xfc, 0xc9, 0xa4, 0x7c, 0x1c, 0x40, 0x34,
	0xc9, 0x85, 0x3f, 0xdb, 0xd1, 0x0c, 0x19, 0xfc, 0x08, 0x8b, 0x1e, 0x08, 0x9f, 0x4d, 0x3b, 0xff,
	0x01, 0xe9, 0xfe, 0x7b, 0xb1, 0x5d, 0xbb, 0x20, 0xde, 0x0d, 0x7e, 0x80, 0x99, 0x81, 0xc2, 0x2b,
	0x11, 0xd7, 0x99, 0xfe, 0x75, 0x8a, 0xef, 0xdd, 0xe0, 0x3b, 0x98, 0x45, 0xdc, 0xae, 0xce, 0xb5,
	0xe2, 0xab, 0x7d, 0x8f, 0x73, 0xa3, 0xbc, 0xf9, 0x15, 0x00, 0x00, 0xff, 0xff, 0x04, 0x2d, 0xb4,
	0x09, 0xd6, 0x02, 0x00, 0x00,
}
