package utils

import debVer "github.com/knqyf263/go-deb-version"

func IsLessThanDebianVersion(v1, v2 string) bool {
	debV1, _ := debVer.NewVersion(v1)
	debV2, _ := debVer.NewVersion(v2)
	return debV1.LessThan(debV2)
}
