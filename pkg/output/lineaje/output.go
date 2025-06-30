package lineaje

import (
	"encoding/json"
	"os"
	"time"

	"github.com/project-copacetic/copacetic/pkg/types"
)

var version string

type imageDetails struct {
	Platform           string `json:"platform"`
	PatchedImage       string `json:"patched_image"`
	PatchedImageDigest string `json:"patched_image_digest"`
}

type Output struct {
	Schema           string              `json:"schema_no"`
	Status           string              `json:"status"`
	Message          string              `json:"message"`
	ImageDetails     imageDetails        `json:"image_details"`
	PatchesApplied   []types.PatchDetail `json:"patches_applied"`
	PatchesFailed    map[string]string   `json:"patches_failed"`
	CopaceticVersion string              `json:"copacetic_version"`
	StartTime        string              `json:"start_time"`
	EndTime          string              `json:"end_time"`
	ScannerVersion   string              `json:"scanner_version"`
}

// NewLineajeOutput creates an Output instance initialized with provided patch error, result, start time, and scanner version.
// It sets the status as "success" or "failure" based on the error presence and populates patch details if available.
func NewLineajeOutput(
	patchError error,
	patchResult *types.PatchResult,
	startTime string,
) Output {
	lineajeOutput := Output{
		Schema:    "1.0",
		Status:    "success",
		StartTime: startTime,
		EndTime:   time.Now().Format(time.RFC3339),
	}
	lineajeOutput.CopaceticVersion = "copacetic " + version
	if patchError != nil {
		lineajeOutput.Status = "failure"
		lineajeOutput.Message = patchError.Error()
	}
	if patchResult != nil {
		lineajeOutput.ScannerVersion = patchResult.PluginVersion
		lineajeOutput.ImageDetails = newImageDetails("local", patchResult.PatchedRef.String(), patchResult.PatchedImageDigest)
		lineajeOutput.PatchesApplied = patchResult.PatchesApplied
		lineajeOutput.PatchesFailed = make(map[string]string)
		for _, patchDetail := range patchResult.PatchesFailed {
			lineajeOutput.PatchesFailed[patchDetail.InstalledPURL] = patchDetail.ErrorMsg
		}
	}
	return lineajeOutput
}

// Save writes to the given file as pretty-printed JSON.
func (o *Output) Save(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(o)
}

// newImageDetails constructs an imageDetails instance.
func newImageDetails(
	platform string,
	patchedImage string,
	patchedImageDigest string,
) imageDetails {
	return imageDetails{
		Platform:           platform,
		PatchedImage:       patchedImage,
		PatchedImageDigest: patchedImageDigest,
	}
}
