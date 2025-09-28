package integration

import (
	"context"
	"os"
	"testing"

	"github.com/lineaje-labs/copacetic/test/integration/integration_utils"
)

func TestIntegrationAPK(t *testing.T) {
	ctx := context.Background()

	// Get current working directory
	wd, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get path of current working directory: %v", err)
		return
	}

	// Get version comparer for apk
	apkComparer := integration_utils.VersionComparer{IsValid: integration_utils.IsValidAPKVersion, LessThan: integration_utils.IsLessThanAPKVersion}

	tests := []integration_utils.Test{
		{
			Name:                   "alpine 3.17.0_rc1 image should be patched successfully",
			InputFilePath:          "testresources/apk/alpine/alpine_3_17_0_rc1_input.json",
			ExpectedOutputFilePath: "testresources/apk/alpine/alpine_3_17_0_rc1_expected_output.json",
			ActualOutputFilePath:   "testresources/apk/alpine/alpine_3_17_0_rc1_actual_output.json",
			TestContainerName:      "alpine:3.17.0_rc1",
			ReusableContainerName:  "copa_alpine_test_container",
			SetupTestContainer:     true,
			Args:                   []string{"patch", "--scanner", "lineaje-scanner", "-f", "lineaje"},
			PURLsExpectedToFail:    []string{},
			WantErr:                false,
			VersionComparer:        apkComparer,
		},
		{
			Name:                   "alpine 3.17.0_rc1 image should be patched successfully for invalid package name", // ssl_client_invalid@1.100.1
			InputFilePath:          "testresources/apk/alpine/alpine_3_17_0_rc1_invalid_package_input.json",
			ExpectedOutputFilePath: "testresources/apk/alpine/alpine_3_17_0_rc1_invalid_package_input_expected_output.json",
			ActualOutputFilePath:   "testresources/apk/alpine/alpine_3_17_0_rc1_invalid_package_input_actual_output.json",
			TestContainerName:      "alpine:3.17.0_rc1",
			ReusableContainerName:  "copa_alpine_test_container",
			SetupTestContainer:     true,
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
