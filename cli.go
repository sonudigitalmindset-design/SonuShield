package main

// Command-line interface (Batch 6). Subcommands:
//
//	sonushield run [--wizard] [--wizard-listen=ADDR]
//	sonushield validate [--config PATH]
//	sonushield export [--config PATH] [--include-secrets]
//	sonushield version
//	sonushield help
//
// With no arguments the proxy runs, exactly as before: existing
// systemd units and scripts that invoke the bare binary keep
// working. A leading flag (sonushield --wizard) also runs the
// proxy, preserving the first-run wizard invocation form. Any
// other first argument is an unknown command and prints usage.
//
// validate and export never start the proxy and never touch the
// network: they read the config file, and validate additionally
// applies the same checks a reload would (ValidateConfig,
// including certificate loading). export prints the parsed
// configuration as indented JSON with secrets redacted by
// default; --include-secrets prints a faithful copy and warns
// on stderr. When a secret-bearing config field is added, it
// must be added to redactConfigForExport as well.
//
// version prints the stamped version (dev when built without
// -ldflags) and the Go toolchain version. Release builds stamp
// it with: go build -ldflags "-X main.version=vX.Y.Z".

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"sonushield/core/domains"
	"sonushield/core/server"
	"strings"
)

// version is stamped at release-build time via -ldflags.
// "dev" means an unstamped local build.
var version = "dev"

const cliUsage = `SonuShield — anti-DDoS reverse proxy.

Usage:
  sonushield run [--wizard] [--wizard-listen=ADDR]
      Run the proxy (the default when no subcommand is given).
      --wizard starts the first-run web setup instead, when no
      config.json exists. --wizard-listen sets its listen
      address (default 127.0.0.1:8080, localhost-only).
  sonushield validate [--config PATH]
      Check a config file without starting the proxy. Exits 0
      when the config would load and reload cleanly.
  sonushield export [--config PATH] [--include-secrets]
      Print the config as indented JSON. Secrets are redacted
      unless --include-secrets is given.
  sonushield version
      Print version information.
  sonushield help
      Print this usage text.
`

// cliDispatch handles CLI subcommands. It reports (handled,
// exitCode): handled=false means "run the proxy" (the existing
// main body proceeds). For the run subcommand it strips the word
// "run" from os.Args so the wizard flag scan sees the remaining
// flags exactly as the legacy bare-flag form provides them.
func cliDispatch() (bool, int) {
	args := os.Args[1:]
	if len(args) == 0 {
		return false, 0
	}
	switch args[0] {
	case "run":
		os.Args = append([]string{os.Args[0]}, args[1:]...)
		return false, 0
	case "validate":
		return true, runValidate(os.Stdout, os.Stderr, args[1:])
	case "export":
		return true, runExport(os.Stdout, os.Stderr, args[1:])
	case "version", "--version", "-version":
		fmt.Fprintf(os.Stdout, "SonuShield %s (go %s)\n", version, runtime.Version())
		return true, 0
	case "help", "--help", "-h":
		fmt.Fprint(os.Stdout, cliUsage)
		return true, 0
	}
	if strings.HasPrefix(args[0], "-") {
		// Legacy bare-flag form (e.g. --wizard): run the proxy.
		return false, 0
	}
	fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], cliUsage)
	return true, 2
}

// readCLIConfig reads and parses a config file for validate/export.
func readCLIConfig(path string) (*domains.Configuration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg domains.Configuration
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	return &cfg, nil
}

func runValidate(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "config.json", "config file to validate")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: sonushield validate [--config PATH]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	cfg, err := readCLIConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "validate: "+err.Error())
		return 1
	}
	if err := server.ValidateConfig(cfg); err != nil {
		fmt.Fprintln(stderr, "validate: "+*configPath+" is invalid: "+err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "%s is valid: %d domain(s)\n", *configPath, len(cfg.Domains))
	return 0
}

func runExport(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "config.json", "config file to export")
	includeSecrets := fs.Bool("include-secrets", false, "include secret values (handle the output carefully)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: sonushield export [--config PATH] [--include-secrets]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	cfg, err := readCLIConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "export: "+err.Error())
		return 1
	}
	if *includeSecrets {
		fmt.Fprintln(stderr, "export: output includes secrets; handle it carefully and do not share it.")
	} else {
		redactConfigForExport(cfg)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "export: "+err.Error())
		return 1
	}
	stdout.Write(data)
	stdout.Write([]byte("\n"))
	return 0
}

const redactedSecret = "REDACTED"

// redactConfigForExport replaces every set secret-bearing value
// in cfg with REDACTED, in place. Unset (empty) values stay
// empty, so the export still shows which secrets are configured.
// Paths to certificate/key files are NOT secrets and are kept.
// When a secret-bearing config field is added anywhere, add it
// here too.
func redactConfigForExport(cfg *domains.Configuration) {
	redact := func(value *string) {
		if *value != "" {
			*value = redactedSecret
		}
	}
	redact(&cfg.Proxy.AdminSecret)
	redact(&cfg.Proxy.APISecret)
	// apiRoles maps secret -> role: the KEYS are the secrets.
	// Rebuild with numbered placeholders, keeping the roles, in
	// sorted order so the export is deterministic.
	if len(cfg.Proxy.APIRoles) > 0 {
		roles := make([]string, 0, len(cfg.Proxy.APIRoles))
		for _, role := range cfg.Proxy.APIRoles {
			roles = append(roles, role)
		}
		sort.Strings(roles)
		redacted := make(map[string]string, len(roles))
		for i, role := range roles {
			redacted[fmt.Sprintf("%s-%d", redactedSecret, i+1)] = role
		}
		cfg.Proxy.APIRoles = redacted
	}
	for key, value := range cfg.Proxy.Secrets {
		if value != "" {
			cfg.Proxy.Secrets[key] = redactedSecret
		}
	}
	if cfg.Proxy.SSO != nil {
		redact(&cfg.Proxy.SSO.ClientSecret)
	}
	for i := range cfg.Domains {
		d := &cfg.Domains[i]
		redact(&d.Webhook.URL)
		redact(&d.Telegram.BotToken)
		redact(&d.Email.Password)
		redact(&d.Twilio.AuthToken)
		redact(&d.ChallengeSecretKey)
		redact(&d.JWTSecret)
		redact(&d.OriginLockSecret)
		for j := range d.APIKeys {
			redact(&d.APIKeys[j].Key)
		}
	}
}
