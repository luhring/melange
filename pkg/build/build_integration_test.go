//go:build integration
// +build integration

package build

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"io"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/container/docker"
	"github.com/google/go-cmp/cmp"
)

func TestBuild_BuildPackage(t *testing.T) {
	tests := []struct {
		name            string
		expectedVersion string
	}{
		{
			name:            "crane",
			expectedVersion: "0.20.2-r1",
		},
	}

	const arch = "x86_64"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			p := filepath.Join("testdata", "build_configs", tt.name) + ".yaml"

			t.Run("builds successfully", func(t *testing.T) {
				ctx := context.Background()

				buildAPK(ctx, t, buildAPKOpts{
					configPath: p,
					outDir:     tempDir,
					arch:       arch,
				})

				t.Run("sbom correctness", func(t *testing.T) {
					apkPath := filepath.Join(tempDir, arch, fmt.Sprintf("%s-%s.apk", tt.name, tt.expectedVersion))
					apkFile, err := os.Open(apkPath)
					if err != nil {
						t.Fatalf("opening apk: %v", err)
					}
					defer apkFile.Close()

					gr, err := gzip.NewReader(apkFile)
					if err != nil {
						t.Fatalf("creating gzip reader: %v", err)
					}
					defer gr.Close()

					tr := tar.NewReader(gr)
					var sbom io.Reader
					sbomPath := fmt.Sprintf("var/lib/db/sbom/%s-%s.spdx.json", tt.name, tt.expectedVersion)
					for {
						hdr, err := tr.Next()
						if err != nil {
							t.Fatalf("reading tar header: %v", err)
						}
						if hdr.Name == sbomPath {
							sbom = tr
							break
						}
					}
					if sbom == nil {
						t.Fatalf("SBOM not found in apk: %s", sbomPath)
					}

					expectedSBOMPath := filepath.Join("testdata", "goldenfiles", "sboms", fmt.Sprintf("%s-%s.spdx.json", tt.name, tt.expectedVersion))
					expectedSbomFile, err := os.Open(expectedSBOMPath)
					if err != nil {
						t.Fatalf("opening expected SBOM: %v", err)
					}

					expected, err := io.ReadAll(expectedSbomFile)
					if err != nil {
						t.Fatalf("reading expected SBOM: %v", err)
					}
					actual, err := io.ReadAll(sbom)
					if err != nil {
						t.Fatalf("reading actual SBOM: %v", err)
					}

					if diff := cmp.Diff(expected, actual); diff != "" {
						t.Fatalf("SBOMs differ: \n%s\n", diff)
					}
				})
			})
		})
	}
}

type buildAPKOpts struct {
	configPath, outDir, arch string
}

func buildAPK(ctx context.Context, t *testing.T, opts buildAPKOpts) {
	r := getRunner(ctx, t)

	b, err := New(
		ctx,
		WithConfig(opts.configPath),
		WithOutDir(opts.outDir),
		WithArch(apko_types.Architecture(opts.arch)),
		WithConfigFileRepositoryURL("https://github.com/wolfi-dev/os"),
		WithConfigFileRepositoryCommit("c0ffee"),
		WithRunner(r),
		WithNamespace("wolfi"),
		WithExtraRepos([]string{"https://packages.wolfi.dev/os"}),
		WithExtraKeys([]string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}),
	)
	if err != nil {
		t.Fatalf("setting up build: %v", err)
	}

	if err := b.BuildPackage(ctx); err != nil {
		t.Fatalf("building package: %v", err)
	}
}

type fetchAPKOpts struct {
	installable  apk.InstallablePackage
	outDir, arch string
}

func fetchAPK(ctx context.Context, t *testing.T, opts fetchAPKOpts) {
	client, err := apk.New(
		apk.WithArch(opts.arch),
	)
	if err != nil {
		t.Fatalf("creating apk client: %v", err)
	}

	apkName := opts.installable.PackageName()

	rc, err := client.FetchPackage(ctx, opts.installable)
	if err != nil {
		t.Fatalf("fetching package %q: %v", apkName, err)
	}

	apkDestinationFilePath := filepath.Join(opts.outDir, opts.arch, fmt.Sprintf("%s.apk", apkName))
	apkDestinationFile, err := os.Create(apkDestinationFilePath)
	if err != nil {
		t.Fatalf("creating APK file: %v", err)
	}
	defer apkDestinationFile.Close()
	_, err = io.Copy(apkDestinationFile, rc)
	if err != nil {
		t.Fatalf("writing APK file: %v", err)
	}
}

func getRunner(ctx context.Context, t *testing.T) container.Runner {
	// NOTE: Ideally we have one runner that works everywhere to make it easier to
	// work on these tests. But until then, we'll try to use the most appropriate
	// runner for the environment.

	t.Helper()

	if r := container.BubblewrapRunner(true); r.TestUsability(ctx) {
		return r
	}

	r, err := docker.NewRunner(ctx)
	if err != nil {
		t.Fatalf("creating docker runner: %v", err)
	}
	if r.TestUsability(ctx) {
		return r
	}

	t.Fatal("no usable runner found")
	return nil
}

func TestApkoPackageConsumption(t *testing.T) {
	tests := []struct {
		name        string
		apksToBuild []string
		apksToFetch []string
	}{
		{
			name:        "built-apk", // Using the latest state of APK building.
			apksToBuild: []string{"crane"},
			apksToFetch: nil,
		},
		// {
		// 	name:        "just one fetched APK", // Using an APK from before recent changes to APK building.
		// 	apksToBuild: nil,
		// 	apksToFetch: nil,
		// },
		// {
		// 	name:        "both built and fetched APKs", // To ensure we don't need to rebuild APKs that are already built just to preserve our image building capabilities.
		// 	apksToBuild: nil,
		// 	apksToFetch: nil,
		// },
	}

	const arch = "x86_64"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tempDir := t.TempDir()

			for _, a := range tt.apksToBuild {
				buildAPK(ctx, t, buildAPKOpts{
					configPath: filepath.Join("testdata", "build_configs", a) + ".yaml",
					outDir:     tempDir,
					arch:       arch,
				})
			}

			worldList := append(tt.apksToBuild, tt.apksToFetch...)

			// Do image build using APKs in tempDir.

			opts := []build.Option{
				build.WithArch(arch),
				build.WithTarball(tt.name + ".tar.gz"),
				build.WithImageConfiguration(apko_types.ImageConfiguration{
					Contents: apko_types.ImageContents{
						RuntimeRepositories: []string{filepath.Join(tempDir, "packages"), "https://packages.wolfi.dev/os"},
						Packages:            worldList,
					},
					Archs: []apko_types.Architecture{arch},
				}),
			}

			fs := fs.DirFS(tempDir)
			bc, err := build.New(ctx, fs, opts...)
			if err != nil {
				t.Fatalf("creating build context: %v", err)
			}

			if err := bc.BuildImage(ctx); err != nil {
				t.Fatalf("building image: %v", err)
			}

			// Get SBOM and compare to goldenfile for image SBOM.
			print("test")
		})
	}
}

// installableAPK is a simple implementation of apk.InstallablePackage for
// testing purposes.
type installableAPK struct {
	name, version, arch, checksum string
}

func (i installableAPK) URL() string {
	return fmt.Sprintf("https://packages.wolfi.dev/os/%s/%s-%s.apk", i.arch, i.name, i.version)
}

func (i installableAPK) PackageName() string {
	return i.name
}

func (i installableAPK) ChecksumString() string {
	return i.checksum
}
