// Package transfertools registers the MCP tools of group(s) "transfer":
// tus_upload, s3_multipart_upload, sftp_upload, sftp_download, sftp_list,
// ftp_upload, ftp_download and ftp_list.
package transfertools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/tools"
)

func init() { tools.RegisterGroup(tools.GroupTransfer, register) }

func register(s *mcp.Server, d *tools.Deps) {
	registerTus(s, d)
	registerS3(s, d)
	registerSFTP(s, d)
	registerFTP(s, d)
}
