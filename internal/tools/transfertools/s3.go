package transfertools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/fileio"
	"github.com/HamedFathi/NetKitMCP/internal/progress"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/transfer"
	"github.com/HamedFathi/NetKitMCP/internal/transfer/s3mp"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type s3Creds struct {
	AccessKeyID     string `json:"access_key_id" jsonschema:"AWS access key id"`
	SecretAccessKey string `json:"secret_access_key" jsonschema:"AWS secret access key"`
	SessionToken    string `json:"session_token,omitempty" jsonschema:"session token for temporary credentials"`
}

type s3In struct {
	Bucket         string            `json:"bucket" jsonschema:"bucket name"`
	Key            string            `json:"key" jsonschema:"object key, e.g. backups/2026/db.tar.gz"`
	File           string            `json:"file" jsonschema:"path of the file to upload (inside an allowed read directory)"`
	Endpoint       string            `json:"endpoint,omitempty" jsonschema:"S3-compatible endpoint URL (MinIO, R2, Wasabi, ...); default https://s3.<region>.amazonaws.com"`
	Region         string            `json:"region,omitempty" jsonschema:"signing region (default auth.aws.region, else us-east-1; R2 uses auto)"`
	PathStyle      *bool             `json:"path_style,omitempty" jsonschema:"path-style URLs (endpoint/bucket/key); default true for a custom endpoint, false for AWS (virtual-hosted)"`
	PartSize       int64             `json:"part_size,omitempty" jsonschema:"bytes per part (default 8 MiB, min 5 MiB; raised automatically to stay within 10000 parts)"`
	ContentType    string            `json:"content_type,omitempty" jsonschema:"object Content-Type (default: detected from the file extension)"`
	Metadata       map[string]string `json:"metadata,omitempty" jsonschema:"user metadata (sent as x-amz-meta-<key>)"`
	StorageClass   string            `json:"storage_class,omitempty" jsonschema:"e.g. STANDARD_IA, GLACIER_IR, INTELLIGENT_TIERING"`
	Headers        map[string]string `json:"headers,omitempty" jsonschema:"extra headers for CreateMultipartUpload, e.g. x-amz-acl or x-amz-server-side-encryption"`
	ResumeUploadID string            `json:"resume_upload_id,omitempty" jsonschema:"continue this multipart upload: parts already on the server (matching size/MD5) are skipped"`
	KeepOnFailure  bool              `json:"keep_on_failure,omitempty" jsonschema:"do not abort the multipart upload on failure, so it can be resumed with resume_upload_id"`
	MaxRetries     *int              `json:"max_retries,omitempty" jsonschema:"retries per part on network errors / 5xx (default 3)"`
	AWS            *s3Creds          `json:"aws,omitempty" jsonschema:"credentials (alternatively auth.type=aws_sigv4 with auth.aws)"`
	types.HTTPOptions
	Auth *auth.Config `json:"auth,omitempty" jsonschema:"aws_sigv4 credentials (auth.aws); other auth types are not used for S3"`
}

func registerS3(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "s3_multipart_upload", "S3 multipart upload",
		"Upload a local file to S3 or an S3-compatible store (MinIO, R2, ...) with a SigV4-signed multipart upload: CreateMultipartUpload, UploadPart (streamed from disk, retried), CompleteMultipartUpload. "+
			"On failure the upload is aborted unless keep_on_failure=true; resume a kept upload with resume_upload_id. "+
			"For a single presigned URL use http_upload instead. timeout_seconds applies per request (each part).",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in s3In) (any, error) {
			return runS3(ctx, req, d, in)
		})
}

func runS3(ctx context.Context, req *mcp.CallToolRequest, d *tools.Deps, in s3In) (any, error) {
	start := time.Now()
	if in.Bucket == "" || in.Key == "" {
		return nil, errors.New("bucket and key are required")
	}
	var creds aws.Credentials
	region := in.Region
	switch {
	case in.AWS != nil:
		creds = aws.Credentials{AccessKeyID: in.AWS.AccessKeyID, SecretAccessKey: in.AWS.SecretAccessKey, SessionToken: in.AWS.SessionToken}
	case in.Auth != nil && in.Auth.Kind() == "aws_sigv4" && in.Auth.AWS != nil:
		a := in.Auth.AWS
		creds = aws.Credentials{AccessKeyID: a.AccessKeyID, SecretAccessKey: a.SecretAccessKey, SessionToken: a.SessionToken}
		if region == "" {
			region = a.Region
		}
		if a.Service != "" && a.Service != "s3" {
			return nil, fmt.Errorf("auth.aws.service is %q; S3 multipart uploads are signed for service s3", a.Service)
		}
	case in.Auth != nil && in.Auth.Kind() != "none":
		return nil, fmt.Errorf("auth type %q is not supported for S3; use auth.type=aws_sigv4 with auth.aws or the aws object", in.Auth.Kind())
	default:
		return nil, errors.New("credentials are required: set aws.access_key_id and aws.secret_access_key (or auth.type=aws_sigv4 with auth.aws)")
	}
	if region == "" {
		region = "us-east-1"
	}
	pathStyle := types.BoolDefault(in.PathStyle, in.Endpoint != "")
	if !pathStyle && strings.Contains(in.Bucket, ".") && (in.Endpoint == "" || strings.HasPrefix(in.Endpoint, "https://")) {
		pathStyle = true // dotted bucket names break virtual-hosted TLS
	}
	retries := 3
	if in.MaxRetries != nil {
		retries = min(max(*in.MaxRetries, 0), 20)
	}

	src, err := openSource(d, in.File)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	ctype := in.ContentType
	if ctype == "" {
		ctype = fileio.DetectContentType(src.name, nil)
	}

	// The S3 signer is applied here, so the shared client gets no auth.
	opts := in.HTTPOptions
	c, err := d.NewHTTPClient(opts, nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	hasher := transfer.NewSeqHasher(src.f)
	rep := progress.FromRequest(req)
	res, err := s3mp.Upload(ctx, s3mp.Options{
		Client:         c.Client,
		UserAgent:      c.UserAgent(),
		Endpoint:       in.Endpoint,
		Region:         region,
		Bucket:         in.Bucket,
		Key:            in.Key,
		PathStyle:      pathStyle,
		Credentials:    creds,
		File:           src.f,
		Size:           src.info.Size(),
		PartSize:       in.PartSize,
		ContentType:    ctype,
		Metadata:       in.Metadata,
		StorageClass:   in.StorageClass,
		Headers:        tools.Headers(in.Headers),
		ResumeUploadID: in.ResumeUploadID,
		KeepOnFailure:  in.KeepOnFailure,
		MaxRetries:     retries,
		RequestTimeout: c.Timeout,
		Observe:        hasher.Feed,
		Progress:       rep.Func(ctx, "s3 upload "+src.name),
	})
	if err != nil {
		return nil, ctxErr(ctx, err)
	}
	sum, err := hasher.Finish(src.info.Size())
	if err != nil {
		return nil, fmt.Errorf("hashing %s: %w", src.name, err)
	}
	out := newResult()
	out.File = src.fileInfo(sum, ctype)
	out.BytesTransferred = res.BytesSent
	out.ResumedFrom = res.ResumedFrom
	out.Parts = res.Parts
	loc := res.Location
	if loc == "" {
		loc = res.ObjectURL
	}
	out.Remote = types.RemoteInfo{Status: res.Status, Location: loc, ETag: res.ETag, Path: in.Bucket + "/" + strings.TrimPrefix(in.Key, "/")}
	out.Meta["upload_id"] = res.UploadID
	out.Meta["part_size"] = res.PartSize
	out.Meta["parts_uploaded"] = res.PartsUploaded
	out.Meta["parts_skipped"] = res.PartsSkipped
	out.Meta["retries"] = res.Retries
	out.Meta["region"] = region
	out.Meta["path_style"] = pathStyle
	out.Warnings = append(out.Warnings, res.Warnings...)
	if c.Insecure {
		out.Warnings = append(out.Warnings, "TLS certificate verification was disabled (insecure_skip_verify)")
	}
	return finish(out, start), nil
}
