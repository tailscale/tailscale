package main

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
)

func main() {
	var s Server
	s.lc = new(local.Client)

	// Create MCP server
	s.ms = server.NewMCPServer(
		"Tailscale",
		"1.0.0",
	)

	// Add tool
	toolStatus := mcp.NewTool("get_connection_status",
		mcp.WithDescription("Check Tailscale's connection status"),
		// mcp.WithString("name",
		//     mcp.Required(),
		//     mcp.Description("Name of the person to greet"),
		// ),
	)

	s.ms.AddTool(toolStatus, s.statusHandler)

	toolUp := mcp.NewTool("up",
		mcp.WithDescription("Turn Tailscale on (run 'tailscale up')"),
	)
	s.ms.AddTool(toolUp, s.upHandler)

	toolDown := mcp.NewTool("down",
		mcp.WithDescription("Turn Tailscale off (run 'tailscale down')"),
	)
	s.ms.AddTool(toolDown, s.downHandler)

	// Start the stdio server
	if err := server.ServeStdio(s.ms); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

type Server struct {
	lc *local.Client
	ms *server.MCPServer
}

func (s *Server) statusHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	status, err := s.lc.StatusWithoutPeers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection status: %w", err)
	}
	switch status.BackendState {
	case "NoState":
		return mcp.NewToolResultText("In 'NoState', meaning it's broken or wedged or hung or maybe very early in its startup life cycle. But probably broken."), nil
	case "Starting":
		return mcp.NewToolResultText("In 'Starting', meaning it's starting up, but not yet fully connected. In particular, the control plane connection might be up, but no DERP yet."), nil
	default:
		return mcp.NewToolResultText(status.BackendState), nil
	}
}

func (s *Server) upHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_, err := s.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs: ipn.Prefs{
			WantRunning: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to turn on Tailscale: %w", err)
	}
	return mcp.NewToolResultText("done"), nil
}

func (s *Server) downHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_, err := s.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs: ipn.Prefs{
			WantRunning: false,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to turn off Tailscale: %w", err)
	}
	return mcp.NewToolResultText("done"), nil
}
