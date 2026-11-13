// Package all links every tool family into the binary. Each family package
// registers its tools with tools.RegisterGroup from an init function.
package all

import (
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/apitools"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/authtools"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/brokertools"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/grpctools"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/httptools"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/lowtools"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/msgtools"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/soaptools"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/transfertools"
	_ "github.com/HamedFathi/NetKitMCP/internal/tools/wstools"
)
