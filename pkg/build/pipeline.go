// Copyright 2022 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package build

import (
	"context"
	"embed"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/chainguard-dev/clog"
	purl "github.com/package-url/packageurl-go"

	"chainguard.dev/melange/pkg/cond"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/util"
)

type PipelineBuild struct {
	Build      *Build
	Test       *Test
	Package    *config.Package
	Subpackage *config.Subpackage
}

// GetConfiguration returns the configuration for the current pipeline.
// This is either for the Test or the Build
func (pb *PipelineBuild) GetConfiguration() *config.Configuration {
	if pb.Test != nil {
		return &pb.Test.Configuration
	}
	return &pb.Build.Configuration
}

func MutateWith(pb *PipelineBuild, with map[string]string) (map[string]string, error) {
	nw, err := substitutionMap(pb)
	if err != nil {
		return nil, err
	}

	for k, v := range with {
		// already mutated?
		if strings.HasPrefix(k, "${{") {
			nw[k] = v
		} else {
			nk := fmt.Sprintf("${{inputs.%s}}", k)
			nw[nk] = v
		}
	}

	// do the actual mutations
	for k, v := range nw {
		nval, err := util.MutateStringFromMap(nw, v)
		if err != nil {
			return nil, err
		}
		nw[k] = nval
	}

	return nw, nil
}

func substitutionMap(pb *PipelineBuild) (map[string]string, error) {
	nw := map[string]string{
		config.SubstitutionPackageName:        pb.Package.Name,
		config.SubstitutionPackageVersion:     pb.Package.Version,
		config.SubstitutionPackageEpoch:       strconv.FormatUint(pb.Package.Epoch, 10),
		config.SubstitutionPackageFullVersion: fmt.Sprintf("%s-r%s", config.SubstitutionPackageVersion, config.SubstitutionPackageEpoch),
		config.SubstitutionTargetsDestdir:     fmt.Sprintf("/home/build/melange-out/%s", pb.Package.Name),
		config.SubstitutionTargetsContextdir:  fmt.Sprintf("/home/build/melange-out/%s", pb.Package.Name),
	}

	// These are not really meaningful for Test, so only use them for build.
	if pb.Build != nil {
		nw[config.SubstitutionHostTripletGnu] = pb.Build.BuildTripletGnu()
		nw[config.SubstitutionHostTripletRust] = pb.Build.BuildTripletRust()
		nw[config.SubstitutionCrossTripletGnuGlibc] = pb.Build.Arch.ToTriplet("gnu")
		nw[config.SubstitutionCrossTripletGnuMusl] = pb.Build.Arch.ToTriplet("musl")
		nw[config.SubstitutionCrossTripletRustGlibc] = pb.Build.Arch.ToRustTriplet("gnu")
		nw[config.SubstitutionCrossTripletRustMusl] = pb.Build.Arch.ToRustTriplet("musl")
		nw[config.SubstitutionBuildArch] = pb.Build.Arch.ToAPK()
		nw[config.SubstitutionBuildGoArch] = pb.Build.Arch.String()
	}

	// Retrieve vars from config
	subst_nw, err := pb.GetConfiguration().GetVarsFromConfig()
	if err != nil {
		return nil, err
	}

	for k, v := range subst_nw {
		nw[k] = v
	}

	// Perform substitutions on current map
	err = pb.GetConfiguration().PerformVarSubstitutions(nw)
	if err != nil {
		return nil, err
	}

	if pb.Subpackage != nil {
		nw[config.SubstitutionSubPkgDir] = fmt.Sprintf("/home/build/melange-out/%s", pb.Subpackage.Name)
		nw[config.SubstitutionTargetsContextdir] = nw[config.SubstitutionSubPkgDir]
	}

	packageNames := []string{pb.Package.Name}
	for _, sp := range pb.GetConfiguration().Subpackages {
		packageNames = append(packageNames, sp.Name)
	}

	for _, pn := range packageNames {
		k := fmt.Sprintf("${{targets.package.%s}}", pn)
		nw[k] = fmt.Sprintf("/home/build/melange-out/%s", pn)
	}

	for k := range pb.GetConfiguration().Options {
		nk := fmt.Sprintf("${{options.%s.enabled}}", k)
		nw[nk] = "false"
	}

	if pb.Build != nil {
		for _, opt := range pb.Build.EnabledBuildOptions {
			nk := fmt.Sprintf("${{options.%s.enabled}}", opt)
			nw[nk] = "true"
		}
	}

	return nw, nil
}

func validateWith(data map[string]string, inputs map[string]config.Input) (map[string]string, error) {
	if data == nil {
		data = make(map[string]string)
	}

	for k, v := range inputs {
		if data[k] == "" {
			data[k] = v.Default
		}

		if v.Required && data[k] == "" {
			return data, fmt.Errorf("required input %q for pipeline is missing", k)
		}
	}

	return data, nil
}

func loadPipelineData(dir string, uses string) ([]byte, error) {
	if dir == "" {
		return []byte{}, fmt.Errorf("pipeline directory not specified")
	}

	data, err := os.ReadFile(filepath.Join(dir, uses+".yaml"))
	if err != nil {
		return []byte{}, err
	}

	return data, nil
}

// Build a script to run as part of evalRun
func buildEvalRunCommand(ctx context.Context, pipeline *config.Pipeline, debugOption rune, sysPath string, workdir string, fragment string) []string {
	envExport := "export %s='%s'"
	envArr := []string{}
	for k, v := range pipeline.Environment {
		envArr = append(envArr, fmt.Sprintf(envExport, k, v))
	}
	envString := strings.Join(envArr, "\n")
	script := fmt.Sprintf(`set -e%c
export PATH='%s'
%s
[ -d '%s' ] || mkdir -p '%s'
cd '%s'
%s
exit 0`, debugOption, sysPath, envString, workdir, workdir, workdir, fragment)
	return []string{"/bin/sh", "-c", script}
}

type pipelineRunner struct {
	debug       bool
	interactive bool
	config      *container.Config
	runner      container.Runner
}

func (r *pipelineRunner) runPipeline(ctx context.Context, pipeline *config.Pipeline) (bool, error) {
	log := clog.FromContext(ctx)

	if result, err := shouldRun(pipeline.If); !result {
		return result, err
	}

	debugOption := ' '
	if r.debug {
		debugOption = 'x'
	}

	sysPath := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	workdir := "/home/build"
	if pipeline.WorkDir != "" {
		workdir = pipeline.WorkDir
	}

	// We might have called signal.Ignore(os.Interrupt) as part of a previous debug step,
	// so create a new context to make it possible to cancel the Run.
	if r.interactive {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt)
		defer stop()
	}

	if id := identity(pipeline); id != "???" {
		log.Infof("running step %q", id)
	}

	command := buildEvalRunCommand(ctx, pipeline, debugOption, sysPath, workdir, pipeline.Runs)
	if err := r.runner.Run(ctx, r.config, command...); err != nil {
		if err := r.maybeDebug(ctx, command, workdir, err); err != nil {
			return false, err
		}
	}

	steps := 0

	for _, p := range pipeline.Pipeline {
		if ran, err := r.runPipeline(ctx, &p); err != nil {
			return false, fmt.Errorf("unable to run pipeline: %w", err)
		} else if ran {
			steps++
		}
	}

	if assert := pipeline.Assertions; assert != nil {
		if want := assert.RequiredSteps; want != steps {
			return false, fmt.Errorf("pipeline did not run the required %d steps, only %d", want, steps)
		}
	}

	return true, nil
}

func (r *pipelineRunner) maybeDebug(ctx context.Context, cmd []string, workdir string, runErr error) error {
	if !r.interactive {
		return runErr
	}

	log := clog.FromContext(ctx)

	dbg, ok := r.runner.(container.Debugger)
	if !ok {
		log.Errorf("TODO: Implement Debug() for Runner: %T", r.runner)
		return runErr
	}

	log.Errorf("Step failed: %v\n%s", runErr, strings.Join(cmd, " "))
	log.Info(fmt.Sprintf("Execing into pod %q to debug interactively.", r.config.PodID), "workdir", workdir)
	log.Infof("Type 'exit 0' to continue the next pipeline step or 'exit 1' to abort.")

	// If the context has already been cancelled, return before we mess with it.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Don't cancel the context if we hit ctrl+C while debugging.
	signal.Ignore(os.Interrupt)

	if dbgErr := dbg.Debug(ctx, r.config, []string{"/bin/sh", "-c", fmt.Sprintf("cd %s && exec /bin/sh", workdir)}...); dbgErr != nil {
		return fmt.Errorf("failed to debug: %w; original error: %w", dbgErr, runErr)
	}

	// Reset to the default signal handling.
	signal.Reset(os.Interrupt)

	// If Debug() returns succesfully (via exit 0), it is a signal to continue execution.
	return nil
}

func (r *pipelineRunner) runPipelines(ctx context.Context, pipelines []config.Pipeline) error {
	for _, p := range pipelines {
		if _, err := r.runPipeline(ctx, &p); err != nil {
			return fmt.Errorf("unable to run pipeline: %w", err)
		}
	}

	return nil
}

func shouldRun(ifs string) (bool, error) {
	if ifs == "" {
		return true, nil
	}

	result, err := cond.Evaluate(ifs)
	if err != nil {
		return false, fmt.Errorf("evaluating if-conditional %q: %w", ifs, err)
	}

	return result, nil
}

// computeExternalRefs generates PURLs for subpipelines
func computeExternalRefs(uses string, with map[string]string) ([]purl.PackageURL, error) {
	var purls []purl.PackageURL
	var newpurl purl.PackageURL

	switch uses {
	case "fetch":
		args := make(map[string]string)
		args["download_url"] = with["${{inputs.uri}}"]
		if len(with["${{inputs.expected-sha256}}"]) > 0 {
			args["checksum"] = "sha256:" + with["${{inputs.expected-sha256}}"]
		}
		if len(with["${{inputs.expected-sha512}}"]) > 0 {
			args["checksum"] = "sha512:" + with["${{inputs.expected-sha512}}"]
		}
		newpurl = purl.PackageURL{
			Type:       "generic",
			Name:       with["${{inputs.purl-name}}"],
			Version:    with["${{inputs.purl-version}}"],
			Qualifiers: purl.QualifiersFromMap(args),
		}
		if err := newpurl.Normalize(); err != nil {
			return nil, err
		}
		purls = append(purls, newpurl)

	case "git-checkout":
		repository := with["${{inputs.repository}}"]
		if strings.HasPrefix(repository, "https://github.com/") {
			namespace, name, _ := strings.Cut(strings.TrimPrefix(repository, "https://github.com/"), "/")
			versions := []string{
				with["${{inputs.tag}}"],
				with["${{inputs.expected-commit}}"],
			}
			for _, version := range versions {
				if version != "" {
					newpurl = purl.PackageURL{
						Type:      "github",
						Namespace: namespace,
						Name:      name,
						Version:   version,
					}
					if err := newpurl.Normalize(); err != nil {
						return nil, err
					}
					purls = append(purls, newpurl)
				}
			}
		} else {
			// Create nice looking package name, last component of uri, without .git
			name := strings.TrimSuffix(filepath.Base(repository), ".git")
			// Encode vcs_url with git+ prefix and @commit suffix
			vcsUrl := "git+" + repository
			if len(with["${{inputs.expected-commit}}"]) > 0 {
				vcsUrl = vcsUrl + "@" + with["${{inputs.expected-commit}}"]
			}
			// Use tag as version
			version := ""
			if len(with["${{inputs.tag}}"]) > 0 {
				version = with["${{inputs.tag}}"]
			}
			newpurl = purl.PackageURL{
				Type:       "generic",
				Name:       name,
				Version:    version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{"vcs_url": vcsUrl}),
			}
			if err := newpurl.Normalize(); err != nil {
				return nil, err
			}
			purls = append(purls, newpurl)
		}
	}
	return purls, nil
}

//go:embed pipelines/*
var f embed.FS
