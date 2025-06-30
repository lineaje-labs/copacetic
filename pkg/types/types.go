package types

import (
	"github.com/distribution/reference"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	InstalledPURL    string `json:"installedPURL"` // LINEAJE: Field that holds the PURL of the vulnerable package that is installed in the image
	FixedVersion     string `json:"fixedVersion"`
	FixedPURL        string `json:"fixedPURL"` // LINEAJE: Field that holds the PURL of the fixed package that was installed in the image
	VulnerabilityID  string `json:"vulnerabilityID"`
}

type UpdatePackages []UpdatePackage

type UpdateManifest struct {
	OSType        string         `json:"osType"`
	OSVersion     string         `json:"osVersion"`
	Arch          string         `json:"arch"`
	Updates       UpdatePackages `json:"updates"`
	PluginVersion string         `json:"pluginVersion"` // LINEAJE: Optional field that holds the details of the Plugin that generated the report
}

// PatchPlatform is an extension of ispec.Platform but with a reportFile.
type PatchPlatform struct {
	ispec.Platform
	ReportFile string `json:"reportFile"`
}

// String returns a string representation of the PatchPlatform.
func (p PatchPlatform) String() string {
	if p.Variant == "" {
		return p.OS + "/" + p.Architecture
	}
	return p.OS + "/" + p.Architecture + "/" + p.Variant
}

// PatchResult represents the result of a single arch patch operation.
type PatchResult struct {
	PluginVersion      string `json:"pluginVersion"` // LINEAJE: Optional field that holds the details of the Plugin that generated the report
	OriginalRef        reference.Named
	PatchedDesc        *ispec.Descriptor
	PatchedRef         reference.Named
	PatchedImageDigest string
	PatchesApplied     []PatchDetail // LINEAJE: List of Patches that were successfully applied
	PatchesFailed      []PatchDetail // LINEAJE: List of Patches that could not be applied
}

// PatchDetail represents the result of a single package operation
type PatchDetail struct {
	Package       string `json:"-"`
	InputVersion  string `json:"-"`
	OutputVersion string `json:"-"`
	InstalledPURL string `json:"input_purl"`
	FixedPURL     string `json:"fixed_purl"`
	ErrorMsg      string `json:"-"`
}
