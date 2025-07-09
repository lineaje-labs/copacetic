package integration

import (
	"context"
	"os"
	"testing"

	"github.com/lineaje-labs/copacetic/test/integration/utils"
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
	apkComparer := utils.VersionComparer{IsValid: utils.IsValidAPKVersion, LessThan: utils.IsLessThanAPKVersion}

	tests := []utils.Test{
		{
			Name:                   "alpine 3.17.0_rc1 image should be patched successfully",
			InputFilePath:          "testresources/apk/alpine/alpine_3_17_0_rc1_input.json",
			ExpectedOutputFilePath: "testresources/apk/alpine/alpine_3_17_0_rc1_expected_output.json",
			ActualOutputFilePath:   "alpine_3_17_0_rc1_actual_output.json",
			TestContainerName:      "alpine:3.17.0_rc1",
			ReusableContainerName:  "copa_alpine_test_container",
			Args:                   []string{"patch", "--scanner", "lineaje-scanner", "-f", "lineaje"},
			WantErr:                false,
		},
		{
			Name:                   "alpine 3.17.0_rc1 image should be patched successfully for invalid package name",
			InputFilePath:          "testresources/apk/alpine/alpine_3_17_0_rc1_invalid_package_input.json",
			ExpectedOutputFilePath: "testresources/apk/alpine/alpine_3_17_0_rc1_invalid_package_input_expected_output.json",
			ActualOutputFilePath:   "alpine_3_17_0_rc1_actual_output.json",
			TestContainerName:      "alpine:3.17.0_rc1",
			ReusableContainerName:  "copa_alpine_test_container",
			Args:                   []string{"patch", "--scanner", "lineaje-scanner", "-f", "lineaje"},
			WantErr:                false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			utils.ValidateIntegrationTest(t, tt, ctx, wd, apkComparer)
		})
	}
}
