package main

import (
	"fmt"
	"sonushield/core/config"
	"sonushield/core/pnc"
	"sonushield/core/proxy"
	"sonushield/core/server"
	"golang.org/x/term"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

var Fingerprint string = "S3LF_BU1LD_0R_M0D1F13D" // 455b9300-0a6f-48f1-82ee-bb1f6cf43500

func main() {

	//CLI subcommands (Batch 6): validate/export/version/help
	//are handled here and exit; anything else runs the proxy.
	if handled, code := cliDispatch(); handled {
		os.Exit(code)
	}

	proxy.Fingerprint = Fingerprint

	logFile, err := os.OpenFile("crash.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	pnc.InitHndl()

	defer pnc.PanicHndl()

	//Disable Error Logging
	log.SetOutput(io.Discard /*logFile*/) // if we ever need to log to a file

	fmt.Println("Starting Proxy ...")

	//First-run setup wizard (Batch 6): --wizard, or no config
	//with a non-terminal stdin, starts the web-based setup
	//instead of the terminal prompts. It never runs when a
	//config already exists.
	if wizardRequested() {
		if _, err := os.Stat("config.json"); err == nil {
			fmt.Println("config.json already exists; the setup wizard only runs on first run.")
			os.Exit(1)
		}
		if err := server.RunWizard(wizardListenAddr()); err != nil {
			fmt.Fprintln(os.Stderr, "Setup wizard: "+err.Error())
			os.Exit(1)
		}
		fmt.Println("Setup complete. Start SonuShield again to run the proxy.")
		return
	}

	config.Load()

	fmt.Println("Loaded Config ...")

	// Wait for everything to be initialised
	fmt.Println("Initialising ...")
	go server.Monitor()
	for !proxy.Initialised {
		time.Sleep(500 * time.Millisecond)
	}

	go server.Serve()

	//Keep server running
	select {}
}

// wizardRequested reports whether the first-run setup wizard
// should run instead of the normal startup: an explicit --wizard
// flag, or no config.json with a non-terminal stdin (systemd,
// Docker, and other non-interactive launches, where the terminal
// prompts cannot work).
func wizardRequested() bool {
	for _, arg := range os.Args[1:] {
		if arg == "--wizard" {
			return true
		}
	}
	if _, err := os.Stat("config.json"); err == nil {
		return false
	}
	return !term.IsTerminal(int(os.Stdin.Fd()))
}

// wizardListenAddr is the wizard's listen address:
// --wizard-listen=ADDR, defaulting to localhost-only.
func wizardListenAddr() string {
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "--wizard-listen=") {
			return strings.TrimPrefix(arg, "--wizard-listen=")
		}
	}
	return "127.0.0.1:8080"
}
