package integration_utils

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	rpmVer "github.com/knqyf263/go-rpm-version"
)

// Depending on go-rpm-version lib for RPM version comparison rules.
func IsValidRPMVersion(v string) bool { // nolint:revive
	err := isValidVersion(v)
	return err == nil
}

func isValidVersion(ver string) error {
	if !unicode.IsDigit(rune(ver[0])) {
		return errors.New("upstream_version must start with digit")
	}

	allowedSymbols := ".-+~:_"
	for _, s := range ver {
		if !unicode.IsDigit(s) && !unicode.IsLetter(s) && !strings.ContainsRune(allowedSymbols, s) {
			return fmt.Errorf("upstream_version %s includes invalid character %q", ver, s)
		}
	}
	return nil
}

func IsLessThanRPMVersion(v1, v2 string) bool {
	rpmV1 := rpmVer.NewVersion(v1)
	rpmV2 := rpmVer.NewVersion(v2)
	return rpmV1.LessThan(rpmV2)
}
