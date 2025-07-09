package utils

type VersionComparer struct {
	IsValid  func(string) bool
	LessThan func(string, string) bool
}

type Test struct {
	Name                   string
	InputFilePath          string
	ExpectedOutputFilePath string
	ActualOutputFilePath   string
	TestContainerName      string
	ReusableContainerName  string
	Args                   []string
	WantErr                bool
}
