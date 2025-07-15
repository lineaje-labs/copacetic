package integration

import (
	"context"
	"os"
	"testing"

	"github.com/lineaje-labs/copacetic/test/integration/integration_utils"
)

func TestIntegrationPublicRepository(t *testing.T) {
	ctx := context.Background()

	// Get current working directory
	wd, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get path of current working directory: %v", err)
		return
	}

	// Get version comparer for apk
	apkComparer := integration_utils.VersionComparer{IsValid: integration_utils.IsValidAPKVersion, LessThan: integration_utils.IsLessThanAPKVersion}
	// Get version comparer for dpkg
	debComparer := integration_utils.VersionComparer{IsValid: integration_utils.IsValidDebianVersion, LessThan: integration_utils.IsLessThanDebianVersion}

	tests := []integration_utils.Test{
		{
			Name:                   "nginx 1.24.4-amd64 image in public ECR registry in AWS should be patched successfully",
			InputFilePath:          "testresources/publicregistry/ecr/public_ecr_nginx_1_21_4_amd64_input.json",
			ExpectedOutputFilePath: "testresources/publicregistry/ecr/public_ecr_nginx_1_21_4_amd64_input_expected_output.json",
			ActualOutputFilePath:   "testresources/publicregistry/ecr/public_ecr_nginx_1_21_4_amd64_input_actual_output.json",
			TestContainerName:      "public.ecr.aws/nginx/nginx:1.21.4-amd64",
			ReusableContainerName:  "copa_public_ecr_nginx_test_container",
			SetupTestContainer:     false,
			Args:                   []string{"patch", "--scanner", "lineaje-scanner", "-f", "lineaje"},
			PURLsExpectedToFail:    []string{},
			WantErr:                false,
			VersionComparer:        debComparer,
		},
		{
			Name:                   "alpine 3.18.0 image in public Docker Hub registry should be patched successfully",
			InputFilePath:          "testresources/publicregistry/dockerhub/public_docker_io_library_alpine_3_18_0_input.json",
			ExpectedOutputFilePath: "testresources/publicregistry/dockerhub/public_docker_io_library_alpine_3_18_0_input_expected_output.json",
			ActualOutputFilePath:   "testresources/publicregistry/dockerhub/public_docker_io_library_alpine_3_18_0_input_actual_output.json",
			TestContainerName:      "docker.io/library/alpine:3.18.0",
			SetupTestContainer:     false,
			ReusableContainerName:  "copa_public_dockerhub_alpine_test_container",
			Args:                   []string{"patch", "--scanner", "lineaje-scanner", "-f", "lineaje"},
			PURLsExpectedToFail:    []string{},
			WantErr:                false,
			VersionComparer:        apkComparer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			integration_utils.ValidateIntegrationTest(t, tt, ctx, wd)
		})
	}
}
