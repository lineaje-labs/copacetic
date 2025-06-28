package pkgmgr

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	apkVer "github.com/knqyf263/go-apk-version"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type apkManager struct {
	config        *buildkit.Config
	workingFolder string
}

// Depending on go-apk-version lib for APK version comparison rules.
func isValidAPKVersion(v string) bool {
	return apkVer.Valid(v)
}

func isLessThanAPKVersion(v1, v2 string) bool {
	apkV1, _ := apkVer.NewVersion(v1)
	apkV2, _ := apkVer.NewVersion(v2)
	return apkV1.LessThan(apkV2)
}

func apkReadResultsManifest(b []byte) ([]string, error) {
	if b == nil {
		return nil, fmt.Errorf("nil buffer provided")
	}

	buf := bytes.NewBuffer(b)

	var lines []string
	fs := bufio.NewScanner(buf)
	for fs.Scan() {
		lines = append(lines, fs.Text())
	}

	return lines, nil
}

func validateAPKPackageVersions(updates unversioned.UpdatePackages, cmp VersionComparer, resultsBytes []byte, ignoreErrors bool) ([]string, error) {
	lines, err := apkReadResultsManifest(resultsBytes)
	if err != nil {
		return nil, err
	}

	// Assert apk info list doesn't contain more entries than expected
	if len(lines) > len(updates) {
		err = fmt.Errorf("expected %d updates, installed %d", len(updates), len(lines))
		log.Error(err)
		return nil, err
	}

	// Not strictly necessary, but sort the two lists to not take a dependency on the
	// ordering behavior of apk info output
	sort.SliceStable(updates, func(i, j int) bool {
		return updates[i].Name < updates[j].Name
	})
	log.Debugf("Required updates: %s", updates)

	sort.SliceStable(lines, func(i, j int) bool {
		return lines[i] < lines[j]
	})
	log.Debugf("Resulting updates: %s", lines)

	// Walk files and check update name is prefix for file name
	// results.manifest file is expected to the `apk info --installed -v <packages ...>` output for the
	// specified packages in the order they were specified in:
	//
	// <package name>-<version>
	// ...
	var allErrors *multierror.Error
	var errorPkgs []string
	lineIndex := 0
	for _, update := range updates {
		expectedPrefix := update.Name + "-"
		if lineIndex >= len(lines) || !strings.HasPrefix(lines[lineIndex], expectedPrefix) {
			log.Warnf("Package %s is not installed, may have been uninstalled during upgrade", update.Name)
			continue
		}

		// Found a match, trim prefix- to get version string
		version := strings.TrimPrefix(lines[lineIndex], expectedPrefix)		
		lineIndex++
		if !cmp.IsValid(version) {
			err := fmt.Errorf("invalid version %s found for package %s", version, update.Name)
			log.Error(err)
			errorPkgs = append(errorPkgs, update.Name)
			allErrors = multierror.Append(allErrors, err)
			continue
		}
		if cmp.LessThan(version, update.FixedVersion) {
			err = fmt.Errorf("downloaded package %s version %s lower than required %s for update", update.Name, version, update.FixedVersion)
			log.Error(err)
			errorPkgs = append(errorPkgs, update.Name)
			allErrors = multierror.Append(allErrors, err)
			continue
		}
		log.Infof("Validated package %s version %s meets requested version %s", update.Name, version, update.FixedVersion)
	}

	if ignoreErrors {
		return errorPkgs, nil
	}

	return errorPkgs, allErrors.ErrorOrNil()
}

func (am *apkManager) InstallUpdates(ctx context.Context, manifest *unversioned.UpdateManifest, ignoreErrors bool) (*llb.State, []string, error) {
	// If manifest is nil, update all packages
	if manifest == nil {
		updatedImageState, _, err := am.upgradePackages(ctx, nil, ignoreErrors)
		if err != nil {
			return updatedImageState, nil, err
		}
		// add validation in the future
		return updatedImageState, nil, nil
	}

	// Resolve set of unique packages to update
	apkComparer := VersionComparer{isValidAPKVersion, isLessThanAPKVersion}
	updates, err := GetUniqueLatestUpdates(manifest.Updates, apkComparer, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}
	if len(updates) == 0 {
		log.Warn("No update packages were specified to apply")
		return &am.config.ImageState, nil, nil
	}
	log.Debugf("latest unique APKs: %v", updates)

	updatedImageState, resultsBytes, err := am.upgradePackages(ctx, updates, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}

	// Validate that the deployed packages are of the requested version or better
	errPkgs, err := validateAPKPackageVersions(updates, apkComparer, resultsBytes, ignoreErrors)
	if err != nil {
		return nil, nil, err
	}

	return updatedImageState, errPkgs, nil
}

// Patch a regular alpine image with:
//   - sh and apk installed on the image
//   - valid apk db state on the image
func (am *apkManager) upgradePackages(ctx context.Context, updates unversioned.UpdatePackages, ignoreErrors bool) (*llb.State, []byte, error) {
	imageStateCurrent := am.config.ImageState
	if am.config.PatchedConfigData != nil {
		imageStateCurrent = am.config.PatchedImageState
	}

	apkUpdated := imageStateCurrent.Run(llb.Shlex("apk update"), llb.WithProxy(utils.GetProxy()), llb.IgnoreCache).Root()

	// If updating all packages, check for upgrades before proceeding with patch
	if updates == nil {
		checkUpgradable := `sh -c "apk list 2>/dev/null | grep -q "upgradable" || exit 1"`
		apkUpdated = apkUpdated.Run(llb.Shlex(checkUpgradable)).Root()
	}

	var apkInstalled llb.State
	var resultManifestBytes []byte
	var err error
	if updates != nil {
		// Install all requested update packages by specifying the version.
		// If specified version doesn't exist then search for installable version for the package on the alpine distro
		var parts []string
		const checkAlpineVersionTemplate = 
									`
										arch="$(apk --print-arch)"
										alpine_version=$(cat /etc/alpine-release)

										# Check if the version contains a release candidate suffix
										if echo "$alpine_version" | grep -q '_rc'; then
											# Extract the base version number (e.g., 3.17 from 3.17.0_rc1)
											alpine_version=$(echo "$alpine_version" | sed -E 's/([0-9]+\.[0-9]+)\..*/\1/')
										fi

										# Now, alpine_version contains the stable version number (e.g., 3.17)
										echo "Using Alpine version: $alpine_version on $arch"
									`
		const apkInstallTemplate = `
										pkg=%[1]s
										req=%[2]s
										echo "Started updagrading $pkg on $alpine_version"
										if apk add --no-cache "$pkg"="$req"; then
  											echo "Version $req for $pkg installed."
										else
											echo "Version $req for $pkg not found — searching for alternatives..."

											# Scrape all versions from Alpine package site, then sort/unique them:
											versions=$(wget -qO- "https://pkgs.alpinelinux.org/packages?name=$pkg&branch=v$alpine_version&arch=$arch" \
												| grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?-r[0-9]+" \
												| sort -V | uniq)

											echo "Available versions: $versions"

											# Pick the next greater version or fallback to the latest:
											next=$(printf "%%s\n" "$versions" | awk -v cur="$req" '$0 > cur { print; exit }')
											[ -z "$next" ] && next=$(printf "%%s\n" "$versions" | tail -n1)

											echo "Selecting next version for $pkg: $next"
											apk add --no-cache "$pkg"="$next"
										fi
									`
		
		pkgStrings := []string{}
		for _, u := range updates {
			pkgStrings = append(pkgStrings, u.Name)
			parts = append(parts, fmt.Sprintf(apkInstallTemplate, u.Name, u.FixedVersion))
		}
		fullCmd := strings.Join(parts, "\n")
		installCmd := fmt.Sprintf("sh -c '%s %s'",  strings.ReplaceAll(checkAlpineVersionTemplate, "'", `'\''`), strings.ReplaceAll(fullCmd, "'", `'\''`))
		apkInstalled = apkUpdated.Run(llb.Shlex(installCmd), llb.WithProxy(utils.GetProxy())).Root()

		// Write updates-manifest to host for post-patch validation
		const outputResultsTemplate = `sh -c 'apk info --installed -v %s > %s; if [[ $? -ne 0 ]]; then echo "WARN: apk info --installed returned $?"; fi'`
		pkgs := strings.Trim(fmt.Sprintf("%s", pkgStrings), "[]")
		outputResultsCmd := fmt.Sprintf(outputResultsTemplate, pkgs, resultManifest)
		mkFolders := apkInstalled.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true)))
		resultsDiff := mkFolders.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).AddMount(resultsPath, llb.Scratch())

		resultManifestBytes, err = buildkit.ExtractFileFromState(ctx, am.config.Client, &resultsDiff, resultManifest)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// if updates is not specified, update all packages
		installCmd := `output=$(apk upgrade --no-cache 2>&1); if [ $? -ne 0 ]; then echo "$output" >>error_log.txt; fi`
		apkInstalled = apkUpdated.Run(buildkit.Sh(installCmd), llb.WithProxy(utils.GetProxy())).Root()

		// Validate no errors were encountered if updating all
		if !ignoreErrors {
			apkInstalled = apkInstalled.Run(buildkit.Sh("if [ -s error_log.txt ]; then cat error_log.txt; exit 1; fi")).Root()
		}
	}

	// If the image has been patched before, diff the base image and patched image to retain previous patches
	if am.config.PatchedConfigData != nil {
		// Diff the base image and patched image to get previous patches
		prevPatchDiff := llb.Diff(am.config.ImageState, am.config.PatchedImageState)

		// Diff the base image and new patches
		newPatchDiff := llb.Diff(apkUpdated, apkInstalled)

		// Merging these two diffs will discard everything in the filesystem that hasn't changed
		// Doing llb.Scratch ensures we can keep everything in the filesystem that has not changed
		combinedPatch := llb.Merge([]llb.State{prevPatchDiff, newPatchDiff})
		squashedPatch := llb.Scratch().File(llb.Copy(combinedPatch, "/", "/"))

		// Merge previous and new patches into the base image
		completePatchMerge := llb.Merge([]llb.State{am.config.ImageState, squashedPatch})

		return &completePatchMerge, resultManifestBytes, nil
	}

	// Diff the installed updates and merge that into the target image
	patchDiff := llb.Diff(apkUpdated, apkInstalled)
	patchMerge := llb.Merge([]llb.State{am.config.ImageState, patchDiff})

	return &patchMerge, resultManifestBytes, nil
}

func (am *apkManager) GetPackageType() string {
	return "apk"
}
