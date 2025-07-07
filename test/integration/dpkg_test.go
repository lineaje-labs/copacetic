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

func TestIntegrationDPKG(t *testing.T) {
	ctx := context.Background()

	// Get current working directory
	wd, err := os.Getwd()
	if err != nil {
		t.Errorf("Failed to get path of current working directory: %v", err)
		return
	}
	tests := []struct {
		name                   string
		fixplan                string
		expectedOutputFilePath string
		actualOutputFilePath   string
		testContainerName      string
		args                   []string
		wantErr                bool
	}{
		{
			name:                   "debian report with available packages",
			fixplan:                "testresources/dpkg/input/debian_fixplan.json",
			expectedOutputFilePath: "testresources/dpkg/expectedoutput/debian_expected_output.json",
			actualOutputFilePath:   "debian_actual_output.json",
			testContainerName:      "dockette/debian:latest",
			args:                   []string{"patch", "--scanner", "lineaje-scanner", "-f", "lineaje"},
			wantErr:                false,
		},
		{
			name:                   "ubuntu report with available packages",
			fixplan:                "testresources/dpkg/input/ubuntu_fixplan.json",
			expectedOutputFilePath: "testresources/dpkg/expectedoutput/ubuntu_expected_output.json",
			actualOutputFilePath:   "ubuntu_actual_output.json",
			testContainerName:      "rancher/healthcheck:v0.3.8",
			args:                   []string{"patch", "--scanner", "lineaje-scanner", "-f", "lineaje"},
			wantErr:                false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// setup each test-containers, we are not re-using the container here because debian and ubuntu are two different images
			container, err := setupTestContainer(ctx, tt.testContainerName)
			if err != nil {
				t.Fatal(err)
			}
			// Clean up the container after the test is complete
			defer container.Terminate(ctx)

			fixplanFileFullPath := filepath.Join(wd, tt.fixplan)
			expectedOutputFileFullPath := filepath.Join(wd, tt.expectedOutputFilePath)
			actualOutputFileFullPath := filepath.Join(wd, tt.actualOutputFilePath)

			// append report and output file path to command args
			tt.args = append(tt.args, "-i", tt.testContainerName, "-r", fixplanFileFullPath, "-o", actualOutputFileFullPath)

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

			var actualCollectionSummary, expectedCollectionSummary lineaje.Output
			err = json.Unmarshal(actualOutputJSONContent, &actualCollectionSummary)
			if err != nil {
				t.Errorf("Failed to get unmarshal the actual collection summary JSON due to - %v", err)
				return
			}

			err = json.Unmarshal(expectedOutputJSONContent, &expectedCollectionSummary)
			if err != nil {
				t.Errorf("Failed to get unmarshal the expected collection summary JSON due to - %v", err)
				return
			}

			sort.Slice(actualCollectionSummary.PatchesApplied, func(i, j int) bool {
				return actualCollectionSummary.PatchesApplied[i].InstalledPURL < actualCollectionSummary.PatchesApplied[j].InstalledPURL
			})

			sort.Slice(expectedCollectionSummary.PatchesApplied, func(i, j int) bool {
				return expectedCollectionSummary.PatchesApplied[i].InstalledPURL < expectedCollectionSummary.PatchesApplied[j].InstalledPURL
			})

			if !reflect.DeepEqual(actualCollectionSummary.PatchesApplied, expectedCollectionSummary.PatchesApplied) {
				t.Errorf("Mismatch in patches_applied:\nExpected: %+v\nActual:   %+v", expectedCollectionSummary.PatchesApplied, actualCollectionSummary.PatchesApplied)
			}

			if !reflect.DeepEqual(actualCollectionSummary.PatchesFailed, expectedCollectionSummary.PatchesFailed) {
				t.Errorf("Mismatch in patches_failed:\nExpected: %+v\nActual:   %+v", expectedCollectionSummary.PatchesFailed, actualCollectionSummary.PatchesFailed)
			}

		})
	}
}
