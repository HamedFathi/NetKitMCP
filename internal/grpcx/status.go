package grpcx

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"

	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// StatusInfo is the gRPC status reported in results.
type StatusInfo struct {
	Code    int    `json:"code"`
	Name    string `json:"name"`
	Message string `json:"message,omitempty"`
	// Details are the decoded google.rpc.Status details ("@type" plus
	// fields); undecodable details carry "value_base64".
	Details []any `json:"details,omitempty"`
}

// OK reports whether the status is OK.
func (s StatusInfo) OK() bool { return s.Code == 0 }

var codeNames = []string{
	"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND",
	"ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION",
	"ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS",
	"UNAUTHENTICATED",
}

// CodeName returns the canonical upper-case name of a gRPC code.
func CodeName(code int) string {
	if code >= 0 && code < len(codeNames) {
		return codeNames[code]
	}
	return "CODE(" + strconv.Itoa(code) + ")"
}

// StatusFromError converts an RPC error (nil = OK) to a StatusInfo,
// decoding details with res.
func StatusFromError(err error, res TypeResolver) StatusInfo {
	if err == nil {
		return StatusInfo{Code: 0, Name: "OK"}
	}
	st, ok := status.FromError(err)
	if !ok {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			st = status.New(codes.DeadlineExceeded, err.Error())
		case errors.Is(err, context.Canceled):
			st = status.New(codes.Canceled, err.Error())
		default:
			st = status.New(codes.Unknown, err.Error())
		}
	}
	return StatusFromProto(st.Proto(), res)
}

// StatusFromProto converts a google.rpc.Status.
func StatusFromProto(sp *spb.Status, res TypeResolver) StatusInfo {
	si := StatusInfo{Code: int(sp.GetCode()), Name: CodeName(int(sp.GetCode())), Message: sp.GetMessage()}
	for _, d := range sp.GetDetails() {
		si.Details = append(si.Details, DecodeAny(d, res))
	}
	return si
}

// StatusFromParts builds a status from a code, message and the raw
// grpc-status-details-bin value (may be nil).
func StatusFromParts(code int, msg string, detailsBin []byte, res TypeResolver) StatusInfo {
	si := StatusInfo{Code: code, Name: CodeName(code), Message: msg}
	if len(detailsBin) > 0 {
		var sp spb.Status
		if err := proto.Unmarshal(detailsBin, &sp); err == nil {
			for _, d := range sp.GetDetails() {
				si.Details = append(si.Details, DecodeAny(d, res))
			}
		}
	}
	return si
}

// DecodeAny renders an Any as JSON ("@type" + fields) when its type is
// known, else as {"@type", "value_base64"}.
func DecodeAny(a *anypb.Any, res TypeResolver) any {
	mo := protojson.MarshalOptions{Resolver: res}
	if res == nil {
		mo.Resolver = NewResolver(nil)
	}
	if b, err := mo.Marshal(a); err == nil {
		var v any
		if json.Unmarshal(b, &v) == nil {
			return v
		}
	}
	return map[string]any{"@type": a.GetTypeUrl(), "value_base64": base64.StdEncoding.EncodeToString(a.GetValue())}
}

// DecodeTyped decodes a binary message given its full type name (as used
// by Connect error details).
func DecodeTyped(typeName string, value []byte, res TypeResolver) (any, bool) {
	if res == nil {
		res = NewResolver(nil)
	}
	a := &anypb.Any{TypeUrl: "type.googleapis.com/" + typeName, Value: value}
	mt, err := res.FindMessageByURL(a.TypeUrl)
	if err != nil {
		return nil, false
	}
	m := mt.New().Interface()
	if err := (proto.UnmarshalOptions{Resolver: res}).Unmarshal(value, m); err != nil {
		return nil, false
	}
	return DecodeAny(a, res), true
}
