package integration

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/output/lineaje"
	"github.com/project-copacetic/copacetic/pkg/patch"
)

func TestIntegrationAPK(t *testing.T) {
	ctx := context.Background()

	// Get current working directory
	wd, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get path of current working directory: %v", err)
		return
	}
	tests := []struct {
		name                   string
		inputFilePath          string
		expectedOutputFilePath string
		actualOutputFilePath   string
		testContainerName      string
		reusableContainerName  string
		args                   []string
		wantErr                bool
	}{
		{
			name:                   "alpine 3.17.0_rc1 image should be patched successfully",
			inputFilePath:          "testresources/apk/alpine/alpine_3_17_0_rc1_input.json",
			expectedOutputFilePath: "testresources/apk/alpine/alpine_3_17_0_rc1_expected_output.json",
			actualOutputFilePath:   "alpine_3_17_0_rc1_actual_output.json",
			testContainerName:      "alpine:3.17.0_rc1",
			reusableContainerName:  "copa_alpine_test_container",
			args:                   []string{"patch", "--scanner", "lineaje-scanner", "-f", "lineaje"},
			wantErr:                false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pull the container images to make patching easier to test
			container, err := setupTestContainer(ctx, tt.testContainerName, tt.reusableContainerName)
			if err != nil {
				t.Fatal(err)
			}
			// Clean up the container after the test is complete
			defer container.Terminate(ctx)

			inputFileFullPath := filepath.Join(wd, tt.inputFilePath)
			expectedOutputFileFullPath := filepath.Join(wd, tt.expectedOutputFilePath)
			actualOutputFileFullPath := filepath.Join(wd, tt.actualOutputFilePath)

			// append the input report in lineaje format, and the output file path to command args
			tt.args = append(tt.args, "-i", tt.testContainerName, "-r", inputFileFullPath, "-o", actualOutputFileFullPath)

			// Create a new command with the test args
			cmd := patch.NewPatchCmd()
			cmd.SetArgs(tt.args)

			// Run the command and capture the output
			err = cmd.Execute()
			if err != nil {
				t.Errorf("Error: %v", err)
			}

			var actualOutputJSONContent, expectedOutputJSONContent []byte
			if tt.expectedOutputFilePath != "" {
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

			if tt.actualOutputFilePath != "" {
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
				t.Errorf("Mismatch in patches_applied:\nExpected: %+v\nActual:   %+v", expectedPatchOutputReport.PatchesApplied, actualPatchOutputReport.PatchesApplied)
			}

			if !reflect.DeepEqual(actualPatchOutputReport.PatchesFailed, expectedPatchOutputReport.PatchesFailed) {
				t.Errorf("Mismatch in patches_failed:\nExpected: %+v\nActual:   %+v", expectedPatchOutputReport.PatchesFailed, actualPatchOutputReport.PatchesFailed)
			}

		})
	}
}
