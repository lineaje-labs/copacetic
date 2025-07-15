package integration

import (
	"context"
	"os"
	"testing"

	"github.com/lineaje-labs/copacetic/test/integration/integration_utils"
)

func TestIntegrationDPKG(t *testing.T) {
	ctx := context.Background()

	// Get the current working directory
	wd, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get path of current working directory: %v", err)
		return
	}

	// Get version comparer for dpkg
	debComparer := integration_utils.VersionComparer{IsValid: integration_utils.IsValidDebianVersion, LessThan: integration_utils.IsLessThanDebianVersion}

	tests := []integration_utils.Test{
		{
			Name:                   "dockette bullseye latest image should be patched successfully",
			InputFilePath:          "testresources/dpkg/debian/dockette_bullseye_input.json",
			ExpectedOutputFilePath: "testresources/dpkg/debian/dockette_bullseye_expected_output.json",
			ActualOutputFilePath:   "testresources/dpkg/debian/dockette_bullseye_actual_output.json",
			TestContainerName:      "dockette/debian:bullseye",
			ReusableContainerName:  "copa_debian_test_container",
			SetupTestContainer:     true,
			Args:                   []string{"patch", "--scanner", "lineaje-scanner", "-f", "lineaje"},
			PURLsExpectedToFail:    []string{},
			WantErr:                false,
			VersionComparer:        debComparer,
		},
		{
			Name:                   "rancher healthcheck v0.3.8 image should be patched successfully",
			InputFilePath:          "testresources/dpkg/ubuntu/rancher_healthcheck_input.json",
			ExpectedOutputFilePath: "testresources/dpkg/ubuntu/rancher_healthcheck_expected_output.json",
			ActualOutputFilePath:   "testresources/dpkg/ubuntu/rancher_healthcheck_actual_output.json",
			TestContainerName:      "rancher/healthcheck:v0.3.8",
			ReusableContainerName:  "copa_ubuntu_test_container",
			SetupTestContainer:     true,
			Args:                   []string{"patch", "--scanner", "lineaje-scanner", "-f", "lineaje"},
			PURLsExpectedToFail:    []string{},
			WantErr:                false,
			VersionComparer:        debComparer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			integration_utils.ValidateIntegrationTest(t, tt, ctx, wd)
		})
	}
}
