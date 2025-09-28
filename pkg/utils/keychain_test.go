package utils

import (
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

func TestGetKeychainForRegistry(t *testing.T) {
	tests := []struct {
		name              string
		imageRef          string
		imageDetail       unversioned.ImageDetail
		expectedKeychain  authn.Keychain
		expectImagePullFn bool
	}{
		{
			name:              "ECR public image",
			imageRef:          "public.ecr.aws/docker/library/alpine:3.18.0",
			imageDetail:       unversioned.ImageDetail{Private: false},
			expectedKeychain:  authn.DefaultKeychain,
			expectImagePullFn: false,
		},
		{
			name:              "ECR private image",
			imageRef:          "216394054222.dkr.ecr.ca-central-1.amazonaws.com/caddy:latest",
			imageDetail:       unversioned.ImageDetail{Private: true},
			expectedKeychain:  amazonKeychain,
			expectImagePullFn: true,
		},
		{
			name:              "DockerHub public image",
			imageRef:          "docker.io/library/alpine:3.18.0",
			imageDetail:       unversioned.ImageDetail{Private: false},
			expectedKeychain:  authn.DefaultKeychain,
			expectImagePullFn: false,
		},
		{
			name:              "DockerHub private image",
			imageRef:          "infrauser/lineaje-demo:1.0.2",
			imageDetail:       unversioned.ImageDetail{Private: true},
			expectedKeychain:  authn.DefaultKeychain,
			expectImagePullFn: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keychain, puller := getKeychainForRegistry(tt.imageRef, tt.imageDetail)

			if !reflect.DeepEqual(keychain, tt.expectedKeychain) {
				t.Errorf("Expected keychain: %#v, got: %#v", tt.expectedKeychain, keychain)
			}

			if (puller.ImagePull != nil) != tt.expectImagePullFn {
				t.Errorf("Expected ImagePull function presence: %v, got: %v", tt.expectImagePullFn, puller.ImagePull != nil)
			}
		})
	}
}
