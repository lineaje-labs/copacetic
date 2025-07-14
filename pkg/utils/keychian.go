package utils

import (
	"io"
	"strings"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

var (
	amazonKeychain authn.Keychain = authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard)))
)

func getKeychainForRegistry(imageRef string, imageDetail unversioned.ImageDetail) (authn.Keychain, unversioned.PrivateRegistryImagePuller) {
	privateImagePuller := unversioned.PrivateRegistryImagePuller{}
	switch {
	case strings.Contains(imageRef, "amazonaws.com"):
		// LINEAJE: In the case of an ECR public repository, Copacetic automatically pulls the image.
		// LINEAJE: In the case of an ECR private repository, we use privateEcrImagePuller, provided that AWS_REGION, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set as environment variables.
		if imageDetail.Private {
			privateImagePuller.ImagePull = ecrImagePull
		}
		return amazonKeychain, privateImagePuller
	default:
		// LINEAJE: In the case of a Docker Hub public repository, Copacetic automatically pulls the image.
		// LINEAJE: In the case of a Docker Hub private repository, Copacetic automatically pulls the image provided that DOCKER_USERNAME and DOCKER_ACCESS_TOKEN are set as environment variables.
		if imageDetail.Private {
			privateImagePuller.ImagePull = dockerHubImagePull
		}
		return authn.DefaultKeychain, privateImagePuller
	}
}
