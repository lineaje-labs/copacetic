package utils

import apkVer "github.com/knqyf263/go-apk-version"

// Depending on go-apk-version lib for APK version comparison rules.
func IsValidAPKVersion(v string) bool {
	return apkVer.Valid(v)
}

func IsLessThanAPKVersion(actualInstalledVersion string, expectedInstalledVersion string) bool {
	apkV1, _ := apkVer.NewVersion(actualInstalledVersion)
	apkV2, _ := apkVer.NewVersion(expectedInstalledVersion)
	return apkV1.LessThan(apkV2)
}
