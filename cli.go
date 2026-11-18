package main

// Command-line interface (Batch 6). Subcommands:
//
//	sonushield run [--wizard] [--wizard-listen=ADDR]
//	sonushield validate [--config PATH]
//	sonushield export [--config PATH] [--include-secrets]
//	sonushield backup [--config PATH] [--output PATH] [--include-secrets]
//	sonushield restore [--config PATH] BACKUP_FILE
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
// backup and restore move whole configurations between
// instances (see core/backup). backup writes a versioned
// envelope with secrets redacted; --include-secrets encrypts
// them under the SONUSHIELD_BACKUP_PASSPHRASE environment
// variable (never a flag: flags leak into shell history and
// process listings). restore validates the envelope before
// writing anything, keeps a .bak copy of the replaced file,
// and never starts the proxy: restart it to apply the
// restored config. Neither command touches the network.
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
	"path/filepath"
	"runtime"
	"sonushield/core/backup"
	"sonushield/core/domains"
	"sonushield/core/server"
	"sort"
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
  sonushield backup [--config PATH] [--output PATH] [--include-secrets]
      Write a backup envelope (config, rules, IP lists,
      tenants). Secrets are redacted unless --include-secrets
      is given, in which case they are encrypted under the
      SONUSHIELD_BACKUP_PASSPHRASE environment variable.
  sonushield restore [--config PATH] BACKUP_FILE
      Validate a backup envelope and write it as the config
      (keeping a .bak copy). A bad backup changes nothing.
      Encrypted backups need SONUSHIELD_BACKUP_PASSPHRASE.
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
	case "backup":
		return true, runBackup(os.Stdout, os.Stderr, args[1:])
	case "restore":
		return true, runRestore(os.Stdout, os.Stderr, args[1:])
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
	// Stripe secret key: never in an export without --include-secrets.
	redact(&cfg.Proxy.Stripe.SecretKey)
	// Public API keys: the Key field of each entry is a secret.
	for i := range cfg.Proxy.PublicAPIKeys {
		redact(&cfg.Proxy.PublicAPIKeys[i].Key)
	}
	// Event webhook endpoints: URLs often contain tokens and
	// the secret signs deliveries — redact both, like the
	// Discord webhook URL.
	for i := range cfg.Proxy.EventWebhooks {
		redact(&cfg.Proxy.EventWebhooks[i].URL)
		redact(&cfg.Proxy.EventWebhooks[i].Secret)
	}
	// Threat-sharing peer secrets: one per peer pairing.
	for i := range cfg.Proxy.ThreatSharing.Peers {
		redact(&cfg.Proxy.ThreatSharing.Peers[i].SharedSecret)
	}
	// BGP monitor API token (custom sources only).
	redact(&cfg.Proxy.BGPMonitor.APIToken)
	// On-call responder channel secrets.
	for i := range cfg.Proxy.OnCall.Responders {
		responder := &cfg.Proxy.OnCall.Responders[i]
		redact(&responder.Telegram.BotToken)
		redact(&responder.Email.Password)
		redact(&responder.Twilio.AuthToken)
		redact(&responder.Webhook.URL)
	}
	for i := range cfg.Domains {
		d := &cfg.Domains[i]
		redact(&d.Webhook.URL)
		redact(&d.Telegram.BotToken)
		redact(&d.Email.Password)
		redact(&d.Twilio.AuthToken)
		redact(&d.ChallengeSecretKey)
		redact(&d.JWTSecret)
		redact(&d.Attestation.Secret)
		redact(&d.OriginLockSecret)
		redact(&d.SignedURLSecret)
		redact(&d.CloudflareAPIToken)
		for j := range d.APIKeys {
			redact(&d.APIKeys[j].Key)
		}
	}
}

const backupPassphraseEnv = "SONUSHIELD_BACKUP_PASSPHRASE"

func runBackup(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "config.json", "config file to back up")
	outputPath := fs.String("output", "", "write the envelope to this file (default: stdout)")
	includeSecrets := fs.Bool("include-secrets", false, "encrypt secrets into the envelope under "+backupPassphraseEnv)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: sonushield backup [--config PATH] [--output PATH] [--include-secrets]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	passphrase := ""
	if *includeSecrets {
		passphrase = os.Getenv(backupPassphraseEnv)
		if passphrase == "" {
			fmt.Fprintln(stderr, "backup: --include-secrets needs "+backupPassphraseEnv+" set")
			return 1
		}
		fmt.Fprintln(stderr, "backup: envelope includes encrypted secrets; guard the file and the passphrase.")
	}
	data, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "backup: "+err.Error())
		return 1
	}
	envelope, err := backup.Create(data, passphrase)
	if err != nil {
		fmt.Fprintln(stderr, "backup: "+err.Error())
		return 1
	}
	envelope = append(envelope, '\n')
	if *outputPath == "" {
		stdout.Write(envelope)
		return 0
	}
	// 0600: the envelope may carry encrypted secrets.
	if err := os.WriteFile(*outputPath, envelope, 0600); err != nil {
		fmt.Fprintln(stderr, "backup: "+err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "backup written to %s\n", *outputPath)
	return 0
}

// writeFileAtomic writes data to path via a temp file in the
// same directory plus rename, preserving path's existing mode
// when it exists, else using 0600.
func writeFileAtomic(path string, data []byte) error {
	mode := os.FileMode(0600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sonushield-restore-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func runRestore(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "config.json", "config file to write")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: sonushield restore [--config PATH] BACKUP_FILE")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	envelope, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "restore: "+err.Error())
		return 1
	}
	current, _ := os.ReadFile(*configPath) // absent on a fresh instance: fine
	resolved, err := backup.PrepareRestore(envelope, current, os.Getenv(backupPassphraseEnv))
	if err != nil {
		fmt.Fprintln(stderr, "restore: "+err.Error())
		return 1
	}
	var cfg domains.Configuration
	if err := json.Unmarshal(resolved, &cfg); err != nil {
		fmt.Fprintln(stderr, "restore: restored config is not valid: "+err.Error())
		return 1
	}
	if err := server.ValidateConfig(&cfg); err != nil {
		fmt.Fprintln(stderr, "restore: restored config failed validation: "+err.Error())
		return 1
	}
	// Everything validated: keep a .bak copy, then swap.
	if len(current) > 0 {
		if err := os.WriteFile(*configPath+".bak", current, 0600); err != nil {
			fmt.Fprintln(stderr, "restore: cannot write backup copy: "+err.Error())
			return 1
		}
	}
	if err := writeFileAtomic(*configPath, append(append([]byte{}, resolved...), '\n')); err != nil {
		fmt.Fprintln(stderr, "restore: "+err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "%s restored: %d domain(s). Restart the proxy to apply it.\n", *configPath, len(cfg.Domains))
	return 0
}
