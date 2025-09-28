package utils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	dockerClient "github.com/docker/docker/client"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	log "github.com/sirupsen/logrus"
)

func getDockerHubAuthConfig(imageDetail unversioned.ImageDetail) (registry.AuthConfig, error) {
	username := os.Getenv("DOCKER_USERNAME")
	password := os.Getenv("DOCKER_ACCESS_TOKEN")
	if username == "" || password == "" {
		return registry.AuthConfig{}, fmt.Errorf("DOCKER_USERNAME or DOCKER_ACCESS_TOKEN environment variables not set")
	}

	serverAddress := "https://" + imageDetail.ImageRepository

	authConfig := registry.AuthConfig{
		Username:      username,
		Password:      password,
		ServerAddress: serverAddress,
	}
	return authConfig, nil
}

func getDockerHubEncodedAuthConfig(imageDetail unversioned.ImageDetail) (string, error) {
	authConfig, err := getDockerHubAuthConfig(imageDetail)
	if err != nil {
		return "", err
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth config: %w", err)
	}
	return base64.StdEncoding.EncodeToString(encodedJSON), nil
}

func dockerHubImagePull(ctx context.Context, dockerCli dockerClient.APIClient, imageRef string, imageDetail unversioned.ImageDetail) error {
	authStr, err := getDockerHubEncodedAuthConfig(imageDetail)
	if err != nil {
		log.Errorf("failed to get auth config: %v", err)
		return err
	}

	reader, err := dockerCli.ImagePull(ctx, imageRef, image.PullOptions{
		RegistryAuth: authStr,
	})
	if err != nil {
		log.Errorf("failed to initiate image pull: %v", err)
		return err
	}
	defer reader.Close()

	// Read the stream to make sure the image is fully pulled
	decoder := json.NewDecoder(reader)
	for {
		var statusLine map[string]interface{}
		if err := decoder.Decode(&statusLine); err == io.EOF {
			break // Pull is complete
		} else if err != nil {
			log.Errorf("Error decoding image pull response: %v", err)
			return err
		}
	}

	log.Infof("Image pulled and available locally: %s", imageRef)
	return nil
}
