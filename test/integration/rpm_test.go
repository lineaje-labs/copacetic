package integration

import (
	"context"
	"os"
	"testing"

	"github.com/lineaje-labs/copacetic/test/integration/integration_utils"
)

func TestIntegrationRPM(t *testing.T) {
	ctx := context.Background()

	// Get the current working directory
	wd, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get path of current working directory: %v", err)
		return
	}

	// Get version comparer for rpm
	rpmComparer := integration_utils.VersionComparer{IsValid: integration_utils.IsValidRPMVersion, LessThan: integration_utils.IsLessThanRPMVersion}

	tests := []integration_utils.Test{
		{
			Name:                   "teddysun rpmbuild v9 - dnf image should be patched successfully",
			InputFilePath:          "testresources/rpm/dnf/teddysun_rpmbuild_input.json",
			ExpectedOutputFilePath: "testresources/rpm/dnf/teddysun_rpmbuild_expected_output.json",
			ActualOutputFilePath:   "testresources/rpm/dnf/teddysun_rpmbuild_actual_output.json",
			TestContainerName:      "teddysun/rpmbuild:9",
			ReusableContainerName:  "copa_rpm_dnf_test_container",
			Args:                   []string{"patch", "--scanner", "lineaje-scanner", "-f", "lineaje"},
			PURLsExpectedToFail:    []string{},
			WantErr:                false,
			VersionComparer:        rpmComparer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			integration_utils.ValidateIntegrationTest(t, tt, ctx, wd)
		})
	}
}
