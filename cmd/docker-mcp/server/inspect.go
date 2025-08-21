package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	"github.com/docker/mcp-gateway/cmd/docker-mcp/catalog"
)

type Info struct {
	Tools  []any  `json:"tools"`
	Readme string `json:"readme"`
}

func (s Info) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

func Inspect(ctx context.Context, serverName string) (Info, error) {
	// Try to find the server in any available catalog
	server, err := findServerInCatalogs(serverName)
	if err != nil {
		return Info{}, err
	}

	var (
		tools     []any
		readmeRaw []byte
		errs      errgroup.Group
	)
	
	// If the server has embedded tools, use those
	if len(server.Tools) > 0 {
		for _, tool := range server.Tools {
			tools = append(tools, tool)
		}
	} else if server.ToolsURL != "" {
		// Otherwise fetch from URL if available
		errs.Go(func() error {
			toolsRaw, err := fetch(ctx, server.ToolsURL)
			if err != nil {
				return err
			}

			if err := json.Unmarshal(toolsRaw, &tools); err != nil {
				return err
			}

			return nil
		})
	}
	
	if server.ReadmeURL != "" {
		errs.Go(func() error {
			var err error
			readmeRaw, err = fetch(ctx, server.ReadmeURL)
			if err != nil {
				return err
			}

			return nil
		})
	}
	
	if err := errs.Wait(); err != nil {
		return Info{}, err
	}

	return Info{
		Tools:  tools,
		Readme: string(readmeRaw),
	}, nil
}

// TODO: Should we get all those directly with the catalog?
func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch %s: %s", url, resp.Status)
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// findServerInCatalogs searches for a server across all available catalogs
func findServerInCatalogs(serverName string) (catalog.Tile, error) {
	// First try the Docker catalog
	catalogYAML, err := catalog.ReadCatalogFile(catalog.DockerCatalogName)
	if err == nil {
		var registry catalog.Registry
		if err := yaml.Unmarshal(catalogYAML, &registry); err == nil {
			if server, found := registry.Registry[serverName]; found {
				return server, nil
			}
		}
	}

	// Then try all imported catalogs
	homeDir, _ := os.UserHomeDir()
	catalogDir := filepath.Join(homeDir, ".docker", "mcp", "catalogs")
	
	entries, err := os.ReadDir(catalogDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".yaml" {
				catalogPath := filepath.Join(catalogDir, entry.Name())
				data, err := os.ReadFile(catalogPath)
				if err != nil {
					continue
				}
				
				var registry catalog.Registry
				if err := yaml.Unmarshal(data, &registry); err != nil {
					continue
				}
				
				if server, found := registry.Registry[serverName]; found {
					return server, nil
				}
			}
		}
	}

	return catalog.Tile{}, fmt.Errorf("server %q not found in any catalog", serverName)
}
