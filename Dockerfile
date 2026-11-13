# Optional distroless image. Build: docker build -t netkit-mcp .
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/netkit-mcp .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/netkit-mcp /netkit-mcp
# Files are only readable/writable inside these directories (mount volumes here).
VOLUME ["/data/in", "/data/out"]
ENV NETKIT_ALLOW_READ_DIR=/data/in NETKIT_ALLOW_WRITE_DIR=/data/out
EXPOSE 8080
ENTRYPOINT ["/netkit-mcp"]
# Default: stdio. For HTTP: --transport http --addr 0.0.0.0:8080 --http-token <token>
