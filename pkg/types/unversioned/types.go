package unversioned

type UpdateManifest struct {
	Metadata      Metadata       `json:"metadata"`
	Updates       UpdatePackages `json:"updates"`
	PluginVersion string         `json:"pluginVersion"` // LINEAJE: Optional field that holds the details of the Plugin that generated the report
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
	Arch    string `json:"arch"`
	Variant string `json:"variant"`
}

type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	InstalledPURL    string `json:"installedPURL"` // LINEAJE: Field that holds the PURL of the vulnerable package that is installed in the image
	FixedVersion     string `json:"fixedVersion"`
	FixedPURL        string `json:"fixedPURL"` // LINEAJE: Field that holds the PURL of the fixed package that was installed in the image
	VulnerabilityID  string `json:"vulnerabilityID"`
}
