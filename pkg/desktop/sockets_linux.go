package desktop

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/docker/mcp-gateway/pkg/user"
)

func getDockerDesktopPaths() (DockerDesktopPaths, error) {
	_, err := os.Stat("/run/host-services/backend.sock")
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return DockerDesktopPaths{}, err
		}

		home, err := user.HomeDir()
		if err != nil {
			return DockerDesktopPaths{}, err
		}

		// On Linux: prefer Desktop backend socket exposed under /var/run if present (WSL/Docker Desktop exposes
		// a socket like /var/run/docker-cli.sock). Otherwise fall back to the per-user ~/.docker/desktop paths.
		// This makes the client work b		curl --unix-socket /var/run/docker-cli.sock http://localhost/app/settings | jq .etter in WSL where Desktop may expose sockets in /var/run.
		candidateBackend := filepath.Join(home, ".docker/desktop/backend.sock")
		candidateRaw := filepath.Join(home, ".docker/desktop/docker.raw.sock")
		candidateJFS := filepath.Join(home, ".docker/desktop/jfs.sock")
		candidateTools := filepath.Join(home, ".docker/desktop/tools.sock")

		// Prefer /var/run/docker-cli.sock when available (observed on Docker Desktop WSL integration)
		if _, err := os.Stat("/var/run/docker-cli.sock"); err == nil {
			candidateBackend = "/var/run/docker-cli.sock"
		}

		return DockerDesktopPaths{
			AdminSettingPath:     "/usr/share/docker-desktop/admin-settings.json",
			BackendSocket:        candidateBackend,
			RawDockerSocket:      candidateRaw,
			JFSSocket:            candidateJFS,
			ToolsSocket:          candidateTools,
			CredentialHelperPath: getCredentialHelperPath,
		}, nil
	}

	// Inside LinuxKit
	return DockerDesktopPaths{
		AdminSettingPath:     "/usr/share/docker-desktop/admin-settings.json",
		BackendSocket:        "/run/host-services/backend.sock",
		RawDockerSocket:      "/var/run/docker.sock.raw",
		JFSSocket:            "/run/host-services/jfs.sock",
		ToolsSocket:          "/run/host-services/tools.sock",
		CredentialHelperPath: getCredentialHelperPath,
	}, nil
}

func getCredentialHelperPath() string {
	name := "docker-credential-pass"
	if path, err := exec.LookPath(name); err == nil {
		return path
	}

	return name
}
