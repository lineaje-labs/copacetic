package v1alpha1

const APIVersion string = "v1alpha1"

type UpdateManifest struct {
	APIVersion    string         `json:"apiVersion"`
	Metadata      Metadata       `json:"metadata"`
	Updates       UpdatePackages `json:"updates"`
	PluginVersion string         `json:"pluginVersion"` // LINEAJE: Optional field that holds the details of the Plugin that generated the report
	ImageDetails  ImageDetail    `json:"image_details"` // LINEAJE: Optional field that holds the details of the image that needs to be patched
}

type UpdatePackages []UpdatePackage

type Metadata struct {
	OS     OS     `json:"os"`
	Config Config `json:"config"`
}

type OS struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

type Config struct {
	Arch string `json:"arch"`
}

type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	InstalledPURL    string `json:"installedPURL"` // LINEAJE: Field that holds the PURL of the vulnerable package that is installed in the image
	FixedVersion     string `json:"fixedVersion"`
	FixedPURL        string `json:"fixedPURL"` // LINEAJE: Field that holds the PURL of the fixed package that was installed in the image
	VulnerabilityID  string `json:"vulnerabilityID"`
}

// LINEAJE: Field that holds the details of the image that needs to be patched
type ImageDetail struct {
	Platform        string `json:"platform"`
	ImageRepository string `json:"image_repository"`
	ImageName       string `json:"image_name"`
	ImageVersion    string `json:"image_version"`
	ImageDigest     string `json:"image_digest"`
	Private         bool   `json:"private"`
}
