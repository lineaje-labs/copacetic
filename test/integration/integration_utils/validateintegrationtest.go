package integration_utils

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"testing"

	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/project-copacetic/copacetic/pkg/output/lineaje"
	"github.com/project-copacetic/copacetic/pkg/patch"
)

func ValidateIntegrationTest(t *testing.T, tt Test, ctx context.Context, wd string) {

	// Pull the container images to make patching easier to test
	container, err := setupTestContainer(ctx, tt.TestContainerName, tt.ReusableContainerName)
	if err != nil {
		t.Fatal(err)
	}
	// Clean up the container after the test is complete
	defer container.Terminate(ctx)

	inputFileFullPath := filepath.Join(wd, tt.InputFilePath)
	expectedOutputFileFullPath := filepath.Join(wd, tt.ExpectedOutputFilePath)
	actualOutputFileFullPath := filepath.Join(wd, tt.ActualOutputFilePath)

	// append the input report in lineaje format, and the output file path to command args
	tt.Args = append(tt.Args, "-i", tt.TestContainerName, "-r", inputFileFullPath, "-o", actualOutputFileFullPath)

	// Create a new command with the test args
	cmd := patch.NewPatchCmd()
	cmd.SetArgs(tt.Args)

	// Run the command and capture the output
	err = cmd.Execute()
	if err != nil {
		t.Errorf("Error: %v", err)
	}

	var actualOutputJSONContent, expectedOutputJSONContent []byte
	if tt.ExpectedOutputFilePath != "" {
		var file *os.File

		file, err = os.Open(expectedOutputFileFullPath)
		if err != nil {
			t.Errorf("Failed to open expected output file %s: %v", expectedOutputFileFullPath, err)
			return
		}
		defer file.Close()

		expectedOutputJSONContent, err = io.ReadAll(file)
		if err != nil {
			t.Errorf("Failed to read expected output JSON content: %v", err)
			return
		}
	} else {
		t.Errorf("Expected output file not specified")
		return
	}

	if tt.ActualOutputFilePath != "" {
		var file *os.File
		file, err = os.Open(actualOutputFileFullPath)
		if err != nil {
			t.Errorf("Failed to open actual output file %s: %v", actualOutputFileFullPath, err)
			return
		}
		defer file.Close()

		actualOutputJSONContent, err = io.ReadAll(file)
		if err != nil {
			t.Errorf("Failed to read actual output JSON content: %v", err)
			return
		}
	} else {
		t.Errorf("Actual output file not specified")
		return
	}

	var actualPatchOutputReport, expectedPatchOutputReport lineaje.Output
	err = json.Unmarshal(actualOutputJSONContent, &actualPatchOutputReport)
	if err != nil {
		t.Errorf("Failed to unmarshal the actual patch output report JSON %s due to - %v", actualOutputFileFullPath, err)
		return
	}

	err = json.Unmarshal(expectedOutputJSONContent, &expectedPatchOutputReport)
	if err != nil {
		t.Errorf("Failed to unmarshal the expected patch output report JSON %s due to - %v", expectedOutputFileFullPath, err)
		return
	}

	sort.Slice(actualPatchOutputReport.PatchesApplied, func(i, j int) bool {
		return actualPatchOutputReport.PatchesApplied[i].InstalledPURL < actualPatchOutputReport.PatchesApplied[j].InstalledPURL
	})

	sort.Slice(expectedPatchOutputReport.PatchesApplied, func(i, j int) bool {
		return expectedPatchOutputReport.PatchesApplied[i].InstalledPURL < expectedPatchOutputReport.PatchesApplied[j].InstalledPURL
	})

	if tt.WantErr && expectedPatchOutputReport.Message == "failure" {
		// this is expected failure - in this case test should pass
		return
	}

	if !tt.WantErr && expectedPatchOutputReport.Message == "failure" {
		// this is unexpected failure - in this case test should fail
		t.Errorf("Received unexpected patch report summary error message: %s", expectedPatchOutputReport.Message)
		return
	}

	// if patching is successful then make sure actual patch output matches with expected patch output
	if !reflect.DeepEqual(actualPatchOutputReport.PatchesApplied, expectedPatchOutputReport.PatchesApplied) {
		// There are two possibility to encounter this logic
		// 1. Installed Package(s) is at higher version than the expected version - in this case test should pass
		// 2. Installed package(s) is at below version or the installation met with unexpected error - in this case test should fail

		if len(expectedPatchOutputReport.PatchesApplied) != len(actualPatchOutputReport.PatchesApplied) {
			t.Errorf("Mismatch in lengths of patches_applied:\nExpected: %v\nActual:   %v", expectedOutputFileFullPath, actualOutputFileFullPath)
			return
		}

		for i := range len(expectedPatchOutputReport.PatchesApplied) {

			actualPackageUrl, err := purl.FromString(actualPatchOutputReport.PatchesApplied[i].FixedPURL)
			if err != nil {
				t.Errorf("Failed to get package url for PURL %s due to - %v", actualPatchOutputReport.PatchesApplied[i].FixedPURL, err)
				return
			}
			expectedPackageUrl, err := purl.FromString(expectedPatchOutputReport.PatchesApplied[i].FixedPURL)
			if err != nil {
				t.Errorf("Failed to get package url for PURL %s due to - %v", expectedPatchOutputReport.PatchesApplied[i].FixedPURL, err)
				return
			}

			if !tt.VersionComparer.IsValid(actualPackageUrl.Version) {
				t.Errorf("Invalid version %s found for package %s with PURL %s", actualPackageUrl.Version, actualPackageUrl.Name, actualPatchOutputReport.PatchesApplied[i].FixedPURL)
				t.Errorf("Mismatch in patches_applied:\nExpected output file path: %v\nActual output file path:   %v", expectedOutputFileFullPath, actualOutputFileFullPath)
				return
			}

			if tt.VersionComparer.LessThan(actualPackageUrl.Version, expectedPackageUrl.Version) {
				// we encountered case 2.
				t.Errorf("Installed package %s version %s lower than required %s for update", actualPackageUrl.Name, actualPackageUrl.Version, expectedPackageUrl.Version)
				t.Errorf("Mismatch in patches_applied:\nExpected output file path: %v\nActual output file path:   %v", expectedOutputFileFullPath, actualOutputFileFullPath)
				return
			}
		}
	}

	if !reflect.DeepEqual(actualPatchOutputReport.PatchesFailed, expectedPatchOutputReport.PatchesFailed) {
		for failedPURL := range actualPatchOutputReport.PatchesFailed {
			if slices.Contains(tt.PURLsExpectedToFail, failedPURL) {
				continue
			} else {
				t.Errorf("Failed to install package with purl %s due to - %v", failedPURL, actualPatchOutputReport.PatchesFailed[failedPURL])
				t.Errorf("Mismatch in patches_failed:\nExpected output file path: %v\nActual output file path:   %v", expectedOutputFileFullPath, actualOutputFileFullPath)
				return
			}
		}
	}

}
