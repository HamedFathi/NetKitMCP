package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const unsignedPayload = "UNSIGNED-PAYLOAD"

// emptySHA256 is the hex SHA-256 of an empty payload.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type sigv4Signer struct {
	cfg    *AWSConfig
	signer *v4.Signer
	fixed  time.Time
}

func newSigV4Signer(cfg *AWSConfig) (Signer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth aws_sigv4: the aws object is required")
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("auth aws_sigv4: access_key_id and secret_access_key are required")
	}
	if cfg.Region == "" || cfg.Service == "" {
		return nil, fmt.Errorf("auth aws_sigv4: region and service are required (e.g. us-east-1, execute-api)")
	}
	s := &sigv4Signer{cfg: cfg}
	if cfg.Timestamp != "" {
		t, err := parseAWSTime(cfg.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("auth aws_sigv4 timestamp: %w", err)
		}
		s.fixed = t
	}
	s3 := isS3(cfg.Service)
	s.signer = v4.NewSigner(func(o *v4.SignerOptions) {
		o.DisableURIPathEscaping = s3
	})
	return s, nil
}

func parseAWSTime(v string) (time.Time, error) {
	for _, layout := range []string{"20060102T150405Z", time.RFC3339, time.RFC3339Nano} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("use RFC 3339 or 20060102T150405Z")
}

func isS3(service string) bool {
	switch strings.ToLower(service) {
	case "s3", "s3-object-lambda", "s3express", "s3-outposts":
		return true
	}
	return false
}

// PayloadHash returns the hex SHA-256 of the request body, streaming it via
// GetBody. It returns UNSIGNED-PAYLOAD when the body cannot be re-read.
func PayloadHash(req *http.Request) (string, error) {
	if !hasBody(req) {
		return emptySHA256, nil
	}
	h := sha256.New()
	ok, err := hashBody(req, h)
	if err != nil {
		return "", err
	}
	if !ok {
		return unsignedPayload, nil
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Sign implements Signer.
func (s *sigv4Signer) Sign(ctx context.Context, req *http.Request) error {
	c := s.cfg
	payload := unsignedPayload
	if !c.UnsignedPayload {
		p, err := PayloadHash(req)
		if err != nil {
			return fmt.Errorf("aws_sigv4 payload hash: %w", err)
		}
		payload = p
	}
	if isS3(c.Service) || payload == unsignedPayload {
		req.Header.Set("X-Amz-Content-Sha256", payload)
	}
	t := s.fixed
	if t.IsZero() {
		t = now().UTC()
	}
	creds := aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken}
	return s.signer.SignHTTP(ctx, creds, req, payload, c.Service, c.Region, t)
}
