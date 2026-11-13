package netx

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// UDPRequest describes one UDP exchange: send a datagram, then collect
// replies until MaxResponses arrive or Wait elapses.
type UDPRequest struct {
	Addr         string   // host:port
	Dial         DialFunc // guarded dialer (required); dials "udp"
	Data         []byte
	MaxResponses int           // default 1
	Wait         time.Duration // collection window after sending (default 2s)
	MaxBytes     int64         // total bytes retained across datagrams
}

// Datagram is one received datagram.
type Datagram struct {
	From      string
	Data      []byte
	Size      int
	Truncated bool
	ElapsedMS float64
}

// UDPResult is the outcome of a UDP exchange.
type UDPResult struct {
	Responses  []Datagram
	BytesSent  int
	EndedBy    string
	Error      string
	Truncated  bool
	LocalAddr  string
	RemoteAddr string
	TotalMS    float64
}

// UDPExchange sends one datagram and collects replies. Only replies from
// the target address are accepted (the socket is connected).
func UDPExchange(ctx context.Context, r UDPRequest) (*UDPResult, error) {
	if r.Dial == nil {
		return nil, errors.New("netx: no dialer")
	}
	if r.MaxResponses <= 0 {
		r.MaxResponses = 1
	}
	if r.Wait <= 0 {
		r.Wait = 2 * time.Second
	}
	if r.MaxBytes <= 0 {
		r.MaxBytes = 1 << 20
	}
	if len(r.Data) > 65507 {
		return nil, errors.New("UDP payload is larger than 65507 bytes")
	}
	start := time.Now()
	conn, err := r.Dial(ctx, "udp", r.Addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()

	res := &UDPResult{Responses: []Datagram{}, LocalAddr: conn.LocalAddr().String(), RemoteAddr: conn.RemoteAddr().String()}
	n, err := conn.Write(r.Data)
	res.BytesSent = n
	if err != nil {
		return nil, err
	}
	sentAt := time.Now()
	deadline := sentAt.Add(r.Wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetReadDeadline(deadline)

	var kept int64
	buf := make([]byte, 65535)
	pc, isPacket := conn.(net.PacketConn)
	for {
		var (
			n    int
			from net.Addr
			err  error
		)
		if isPacket {
			n, from, err = pc.ReadFrom(buf)
		} else {
			n, err = conn.Read(buf)
			from = conn.RemoteAddr()
		}
		if err != nil {
			var ne net.Error
			switch {
			case errors.As(err, &ne) && ne.Timeout():
				res.EndedBy = EndedTimeout
			case ctx.Err() != nil:
				res.EndedBy = EndedTimeout
			default:
				res.EndedBy = EndedError
				res.Error = err.Error()
				if strings.Contains(strings.ToLower(err.Error()), "refused") ||
					strings.Contains(strings.ToLower(err.Error()), "forcibly closed") {
					res.Error += " (ICMP port unreachable: nothing is listening on that port)"
				}
			}
			break
		}
		dg := Datagram{Size: n, ElapsedMS: MS(time.Since(sentAt))}
		if from != nil {
			dg.From = from.String()
		}
		data := buf[:n]
		if room := r.MaxBytes - kept; int64(n) > room {
			data = data[:max(room, 0)]
			dg.Truncated = true
			res.Truncated = true
		}
		kept += int64(len(data))
		dg.Data = append([]byte(nil), data...)
		res.Responses = append(res.Responses, dg)
		if len(res.Responses) >= r.MaxResponses {
			res.EndedBy = EndedMaxResp
			break
		}
	}
	res.TotalMS = MS(time.Since(start))
	return res, nil
}
