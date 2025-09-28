package utils

import (
	"context"
	"errors"
	"os"

	dockerClient "github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	log "github.com/sirupsen/logrus"
)

// For testing.
var (
	remoteGet = remote.Get
	newClient = func() (dockerClient.APIClient, error) {
		return dockerClient.NewClientWithOpts(
			dockerClient.FromEnv,
			dockerClient.WithAPIVersionNegotiation(),
		)
	}
)

// GetMediaType returns the manifest’s media type for an image reference
// It prefers a local inspection and falls back to a registry lookup.
func GetMediaType(ctx context.Context, imageRef string, imageDetail unversioned.ImageDetail) (string, error) {
	// Check if the image is local first
	// If it is, use the local media type
	mt, err := localMediaType(imageRef)
	if err == nil && mt != "" {
		log.Debugf("local media type found for %s: %s", imageRef, mt)
		return mt, nil
	}
	log.Debugf("local media type not found for %s: %v", imageRef, err)

	// If the image is not local, use the remote media type
	return remoteMediaType(ctx, imageRef, imageDetail)
}

func localMediaType(imageRef string) (string, error) {
	cli, err := newClient()
	if err != nil {
		return "", err
	}
	defer cli.Close()

	distInspect, err := cli.ImageInspect(context.Background(), imageRef)
	if err != nil {
		return "", err
	}
	if distInspect.Descriptor == nil {
		return "", errors.New("descriptor is nil")
	}
	return distInspect.Descriptor.MediaType, nil
}

func remoteMediaType(ctx context.Context, imageRef string, imageDetail unversioned.ImageDetail) (string, error) {
	cli, err := newClient()
	if err != nil {
		return "", err
	}
	defer cli.Close()

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		log.Debugf("failed to parse reference %s: %v", imageRef, err)
		return "", err
	}

	// LINEAJE: If the remote repository is not Docker Hub, obtain the appropriate authentication keychain to perform remoteGet.
	var desc *remote.Descriptor
	authnKeychain, privateRegistryImagePuller := getKeychainForRegistry(imageRef, imageDetail)
	if imageDetail.Platform == "docker-hub" && imageDetail.Private == true {
		desc, err = remoteGet(ref, remote.WithAuth(authn.FromConfig(authn.AuthConfig{Username: os.Getenv("DOCKER_USERNAME"), Password: os.Getenv("DOCKER_ACCESS_TOKEN")})))
	} else {
		desc, err = remoteGet(ref, remote.WithAuthFromKeychain(authnKeychain))
	}

	if err != nil {
		log.Debugf("failed to get remote media type for %s: %v", imageRef, err)
		return "", err
	}
	log.Debugf("remote media type found for %s: %s", imageRef, desc.MediaType)

	// LINEAJE: If the remote repository is private, pull the image before proceeding with the patch.
	if privateRegistryImagePuller.ImagePull != nil {
		err = privateRegistryImagePuller.ImagePull(ctx, cli, imageRef, imageDetail)
		if err != nil {
			log.Debugf("failed to pull image %s: %v", imageRef, err)
			return "", err
		}
	}
	return string(desc.MediaType), nil
}
