package integration

import (
	"context"
	"os"
	"testing"

	"github.com/lineaje-labs/copacetic/test/integration/integration_utils"
)

func TestIntegrationPrivateRepository(t *testing.T) {
	ctx := context.Background()

	// Get current working directory
	wd, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get path of current working directory: %v", err)
		return
	}

	// Set the environment variables
	os.Setenv("AWS_REGION", "fake-region")
	os.Setenv("AWS_ACCESS_KEY_ID", "fake-access-key-id")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "fake-secret-acess-key")
	os.Setenv("DOCKER_USERNAME", "fake-user")
	os.Setenv("DOCKER_ACCESS_TOKEN", "fake-access-token")

	// Get version comparer for apk
	apkComparer := integration_utils.VersionComparer{IsValid: integration_utils.IsValidAPKVersion, LessThan: integration_utils.IsLessThanAPKVersion}

	tests := []integration_utils.Test{
		{
			Name:                   "caddy latest image in private ECR registry in AWS account 216394054222 should be patched successfully",
			InputFilePath:          "testresources/privateregistry/ecr/216394054222_caddy_lates_input.json",
			ExpectedOutputFilePath: "testresources/privateregistry/ecr/216394054222_caddy_lates_input_expected_output.json",
			ActualOutputFilePath:   "testresources/privateregistry/ecr/216394054222_caddy_lates_input_actual_output.json",
			TestContainerName:      "216394054222.dkr.ecr.ca-central-1.amazonaws.com/caddy:latest", // Private ECR repository. AWS_REGION, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY should be set as environment variables.
			ReusableContainerName:  "copa_private_ecr_caddy_test_container",
			Args:                   []string{"patch", "--scanner", "lineaje-scanner", "-f", "lineaje"},
			PURLsExpectedToFail:    []string{},
			WantErr:                false,
			VersionComparer:        apkComparer,
		},
		{
			Name:                   "lineaje-demo 1.0.2 image in Docker Hub with namespace infrauser should be patched successfully",
			InputFilePath:          "testresources/privateregistry/dockerhub/infrauser_lineaje_demo_1_0_2_input.json",
			ExpectedOutputFilePath: "testresources/privateregistry/dockerhub/infrauser_lineaje_demo_1_0_2_input_expected_output.json",
			ActualOutputFilePath:   "testresources/privateregistry/dockerhub/infrauser_lineaje_demo_1_0_2_input_actual_output.json",
			TestContainerName:      "infrauser/lineaje-demo:1.0.2", // Private Docker Hub repository. DOCKER_USERNAME and DOCKER_ACCESS_TOKEN should be set as environment variables.
			ReusableContainerName:  "copa_private_docker_lineaje_demo_test_container",
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
