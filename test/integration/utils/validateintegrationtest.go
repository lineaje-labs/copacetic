package utils

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/project-copacetic/copacetic/pkg/output/lineaje"
	"github.com/project-copacetic/copacetic/pkg/patch"
)

func ValidateIntegrationTest(t *testing.T, tt Test, ctx context.Context, wd string, comparer VersionComparer) {

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
		defer os.Remove(actualOutputFileFullPath)
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

	if !reflect.DeepEqual(actualPatchOutputReport.PatchesApplied, expectedPatchOutputReport.PatchesApplied) {
		// There are two possibility to encounter this logic
		// 1. Installed Package(s) is at higher version than the expected version - in this case test should pass
		// 2. Installed package(s) is at below version or the installation met with unexpected error - in this case test should fail

		// we assume case 1.
		higherVersionPackageDownloaded := true

		minLen := min(len(expectedPatchOutputReport.PatchesApplied), len(actualPatchOutputReport.PatchesApplied))

		for i := range minLen {
			actualPackageUrl, err := purl.FromString(actualPatchOutputReport.PatchesApplied[i].FixedPURL)
			if err != nil {
				t.Errorf("Failed to get package url for purl %s due to - %v", actualPatchOutputReport.PatchesApplied[i].FixedPURL, err)
				return
			}
			expectedPackageUrl, err := purl.FromString(expectedPatchOutputReport.PatchesApplied[i].FixedPURL)
			if err != nil {
				t.Errorf("Failed to get package url for purl %s due to - %v", expectedPatchOutputReport.PatchesApplied[i].FixedPURL, err)
				return
			}
			if comparer.LessThan(actualPackageUrl.Version, expectedPackageUrl.Version) {
				// we encountered case 2.
				higherVersionPackageDownloaded = false
				t.Errorf("Installed package %s version %s lower than required %s for update", actualPackageUrl.Name, actualPackageUrl.Version, expectedPackageUrl.Version)
			}
		}

		if !higherVersionPackageDownloaded {
			t.Errorf("Mismatch in patches_applied:\nExpected: %+v\nActual:   %+v", expectedPatchOutputReport.PatchesApplied, actualPatchOutputReport.PatchesApplied)
		}
	}

	if !reflect.DeepEqual(actualPatchOutputReport.PatchesFailed, expectedPatchOutputReport.PatchesFailed) {
		t.Errorf("Mismatch in patches_failed:\nExpected: %+v\nActual:   %+v", expectedPatchOutputReport.PatchesFailed, actualPatchOutputReport.PatchesFailed)
	}

}
