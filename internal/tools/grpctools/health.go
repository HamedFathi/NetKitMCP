package grpctools

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"

	"github.com/HamedFathi/NetKitMCP/internal/grpcx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type healthIn struct {
	Target  string `json:"target" jsonschema:"gRPC server host:port (grpc:// = plaintext, grpcs:// = TLS)"`
	Service string `json:"service,omitempty" jsonschema:"service name (empty = overall server health)"`
	Watch   bool   `json:"watch,omitempty" jsonschema:"use the streaming Watch RPC and collect status changes (bounded by max_messages / max_duration_seconds)"`
	types.StreamLimits
	ConnOptions
}

type healthOut struct {
	Target        string              `json:"target"`
	Service       string              `json:"service"`
	ServingStatus string              `json:"serving_status,omitempty"`
	Status        *grpcx.StatusInfo   `json:"status,omitempty"`
	Watch         *types.StreamResult `json:"watch,omitempty"`
	Headers       map[string]string   `json:"headers,omitempty"`
	Trailers      map[string]string   `json:"trailers,omitempty"`
	TimingMS      struct {
		Total float64 `json:"total"`
	} `json:"timing_ms"`
	Warnings []string `json:"warnings,omitempty"`
}

func registerHealth(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "grpc_health_check", "gRPC health check",
		"Run the standard grpc.health.v1 Check RPC (serving_status SERVING / NOT_SERVING / SERVICE_UNKNOWN) for the whole server or one service; "+
			"watch=true runs the Watch stream and collects status updates until max_messages or max_duration_seconds (default 1 message, 10 s).",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in healthIn) (any, error) {
			c, err := dial(d, in.Target, in.ConnOptions)
			if err != nil {
				return nil, err
			}
			defer c.Close()
			out := healthOut{Target: c.target, Service: in.Service, Warnings: c.warnings()}
			client := healthpb.NewHealthClient(c.cc)
			start := time.Now()
			if !in.Watch {
				ctx, cancel := context.WithTimeout(ctx, c.timeout)
				defer cancel()
				octx, err := c.outgoing(ctx, healthpb.Health_Check_FullMethodName)
				if err != nil {
					return nil, err
				}
				var hdr, tr metadata.MD
				resp, err := client.Check(octx, &healthpb.HealthCheckRequest{Service: in.Service}, grpc.Header(&hdr), grpc.Trailer(&tr))
				if g := guardErr(err); g != nil {
					return nil, g
				}
				st := grpcx.StatusFromError(err, nil)
				out.Status = &st
				if resp != nil {
					out.ServingStatus = resp.GetStatus().String()
				}
				out.Headers, out.Trailers = grpcx.MDToMap(hdr), grpcx.MDToMap(tr)
				out.TimingMS.Total = types.MS(time.Since(start))
				return out, nil
			}

			limits := in.StreamLimits
			if limits.MaxMessages <= 0 {
				limits.MaxMessages = 1
			}
			maxMsgs, maxDur, idle := limits.Resolve(d.Cfg.DefaultMaxMessages, d.Cfg.MaxMessages, d.Cfg.DefaultStreamTime, d.Cfg.MaxStreamTime)
			ctx, cancel := context.WithTimeout(ctx, c.timeout+maxDur)
			defer cancel()
			octx, err := c.outgoing(ctx, healthpb.Health_Watch_FullMethodName)
			if err != nil {
				return nil, err
			}
			wctx, wcancel := context.WithCancel(octx)
			defer wcancel()
			col := types.NewCollector(maxMsgs, maxDur, idle, 0)
			stream, err := client.Watch(wctx, &healthpb.HealthCheckRequest{Service: in.Service})
			if err != nil {
				if g := guardErr(err); g != nil {
					return nil, g
				}
				st := grpcx.StatusFromError(err, nil)
				out.Status = &st
				return out, nil
			}
			done := make(chan struct{})
			var final error
			var lastStatus string
			finished := false
			go func() {
				defer close(done)
				for {
					resp, err := stream.Recv()
					if err != nil {
						if errors.Is(err, io.EOF) {
							err = nil
						}
						if wctx.Err() == nil {
							finished, final = true, err
						}
						if err != nil {
							col.Finish(types.EndedError, err)
						} else {
							col.Finish(types.EndedComplete, nil)
						}
						return
					}
					st := resp.GetStatus().String()
					lastStatus = st
					col.Add(types.StreamMessage{Dir: "in", Type: "json", Data: `{"status":"` + st + `"}`, Encoding: "text"})
				}
			}()
			col.Wait(ctx)
			wcancel()
			<-done
			if g := guardErr(final); g != nil {
				return nil, g
			}
			res := col.Result()
			out.Watch = res
			out.ServingStatus = lastStatus
			if finished {
				st := grpcx.StatusFromError(final, nil)
				out.Status = &st
			}
			if h, err := stream.Header(); err == nil {
				out.Headers = grpcx.MDToMap(h)
			}
			out.TimingMS.Total = types.MS(time.Since(start))
			return out, nil
		})
}
