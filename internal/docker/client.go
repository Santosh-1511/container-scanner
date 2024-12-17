package docker

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/api/types"

	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

// wrapping the docker SDK client

type DockerClient struct {
	client *client.Client
}

// creating a new dockerclient
func NewDockerClient() (*DockerClient, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	return &DockerClient{
		client: cli,
	}, nil
}

// Pulls a docker image from registry
func (d *DockerClient) PullImage(ctx context.Context, imageName string) error {
	out, err := d.client.ImagePull(ctx, imageName, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w", imageName, err)
	}
	defer out.Close()

	_, err = io.Copy(io.Discard, out)
	if err != nil {
		return fmt.Errorf("failed to read image pull output: %w", err)
	}

	return nil
}

// gives info about docker image
func (d *DockerClient) GetImageInfo(ctx context.Context, imageName string) (*types.ImageInspect, error) {
	inspect, _, err := d.client.ImageInspectWithRaw(ctx, imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image %s: %w", imageName, err)
	}
	return &inspect, nil
}

// ListPackages : it will list all the packages installed in the image
// asuuming that image is debian/ubuntu based

func (d *DockerClient) ListPackages(ctx context.Context, imageName string) ([]string, error) {
	// creating a container to run the command
	resp, err := d.client.ContainerCreate(ctx,
		&containertypes.Config{
			Image: imageName,
			Cmd:   []string{"/bin/sh", "-c", "dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null || rpm -qa 2>/dev/null"},
			Tty:   true,
		},
		nil, nil, nil, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	//cleaning up container after we're done
	defer func() {
		d.client.ContainerRemove(ctx, resp.ID, containertypes.RemoveOptions{Force: true})
	}()

	//start the container
	if err := d.client.ContainerStart(ctx, resp.ID, containertypes.StartOptions{}); err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// wait for container to finish
	statusCh, errCh := d.client.ContainerWait(ctx, resp.ID, containertypes.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return nil, fmt.Errorf("error waiting for container: %w", err)

		}
	case <-statusCh:
	}
	// Getting logs
	out, err := d.client.ContainerLogs(ctx, resp.ID, containertypes.LogsOptions{ShowStdout: true})
	if err != nil {
		return nil, fmt.Errorf("failed to get container logs: %w", err)
	}
	defer out.Close()

	//Reading logs
	logs, err := io.ReadAll(out)
	if err != nil {
		return nil, fmt.Errorf("failed to read logs: %w", err)
	}

	// splitting output into lines
	packages := []string{}
	for _, line := range strings.Split(string(logs), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			packages = append(packages, line)
		}
	}
	return packages, nil
}
