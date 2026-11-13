package msgtools

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// payloadData is a fully buffered payload (MQTT and NATS messages are
// framed in memory by the protocol libraries, so payloads are bounded).
type payloadData struct {
	Data        []byte
	ContentType string
	File        *types.FileInfo
}

// resolvePayload resolves a Payload into bytes, bounded by maxBytes (and by
// the server upload limit for file payloads).
func resolvePayload(d *tools.Deps, p *types.Payload, maxBytes int64) (*payloadData, error) {
	limit := d.Cfg.UploadBytes(0)
	if maxBytes > 0 && maxBytes < limit {
		limit = maxBytes
	}
	rp, err := p.Resolve(d.Files, d.Cfg.MaxInlineBase64Bytes, limit)
	if err != nil {
		return nil, err
	}
	data, err := rp.Bytes(limit)
	if err != nil {
		return nil, err
	}
	out := &payloadData{Data: data}
	if p != nil && !p.IsZero() {
		out.ContentType = rp.ContentType
	}
	if rp.File != nil {
		fi := *rp.File
		sum := sha256.Sum256(data)
		fi.SHA256 = hex.EncodeToString(sum[:])
		fi.SizeBytes = int64(len(data))
		out.File = &fi
	}
	return out, nil
}

func randomID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func qosByte(q int, field string) (byte, error) {
	if q < 0 || q > 2 {
		return 0, fmt.Errorf("%s must be 0, 1 or 2", field)
	}
	return byte(q), nil
}

func insecureWarning(opts types.TLSOptions, usesTLS bool) []string {
	if opts.InsecureSkipVerify && usesTLS {
		return []string{"insecure_skip_verify=true: the server certificate was not verified"}
	}
	return nil
}

type timingMS struct {
	Connect float64 `json:"connect"`
	Op      float64 `json:"operation"`
	Total   float64 `json:"total"`
}
