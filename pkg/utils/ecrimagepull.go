package utils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	dockerClient "github.com/docker/docker/client"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	log "github.com/sirupsen/logrus"
)

func getECRAuthConfig() (registry.AuthConfig, error) {
	sess := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String(os.Getenv("AWS_REGION")),
		Credentials: credentials.NewStaticCredentials(os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), ""),
	}))

	ecrClient := ecr.New(sess)
	result, err := ecrClient.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		log.Errorf("failed to get ecr client: %v", err)
		return registry.AuthConfig{}, err
	}

	authToken := *result.AuthorizationData[0].AuthorizationToken
	decodedAuth, err := base64.StdEncoding.DecodeString(authToken)
	if err != nil {
		log.Errorf("failed to decode ecr auth token: %v", err)
		return registry.AuthConfig{}, err
	}

	parts := strings.SplitN(string(decodedAuth), ":", 2)
	username := parts[0]
	password := parts[1]
	registryURL := *result.AuthorizationData[0].ProxyEndpoint

	log.Infof("Logging into registry: %s", registryURL)
	authConfig := registry.AuthConfig{
		Username:      username,
		Password:      password,
		ServerAddress: registryURL,
	}

	return authConfig, nil
}

func getECREncodedAuthConfig(imageDetail unversioned.ImageDetail) (string, error) {
	authConfig, err := getECRAuthConfig()
	if err != nil {
		return "", err
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth config: %w", err)
	}
	return base64.URLEncoding.EncodeToString(encodedJSON), nil
}

func ecrImagePull(ctx context.Context, dockerCli dockerClient.APIClient, imageRef string, imageDetail unversioned.ImageDetail) error {
	authStr, err := getECREncodedAuthConfig(imageDetail)
	if err != nil {
		log.Errorf("Failed to get auth config: %v", err)
	}
	reader, err := dockerCli.ImagePull(ctx, imageRef, image.PullOptions{
		RegistryAuth: authStr,
	})
	if err != nil {
		log.Errorf("Failed to initiate image pull: %v", err)
		return err
	}
	defer reader.Close()

	// Read the stream to make sure the image is fully pulled
	decoder := json.NewDecoder(reader)
	var statusLine map[string]interface{}

	for {
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
