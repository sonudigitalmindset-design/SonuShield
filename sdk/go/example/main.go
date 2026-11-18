// Example program for the SonuShield public API client.
//
//	SONUSHIELD_URL=https://example.com SONUSHIELD_API_KEY=your-key go run ./sdk/go/example
package main

import (
	"context"
	"fmt"
	"os"

	"sonushield/sdk/go/sonushield"
)

func main() {
	baseURL := os.Getenv("SONUSHIELD_URL")
	apiKey := os.Getenv("SONUSHIELD_API_KEY")
	if baseURL == "" || apiKey == "" {
		fmt.Fprintln(os.Stderr, "set SONUSHIELD_URL and SONUSHIELD_API_KEY")
		os.Exit(2)
	}
	client := sonushield.NewClient(baseURL, apiKey)
	ctx := context.Background()

	ping, err := client.Ping(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ping:", err)
		os.Exit(1)
	}
	fmt.Printf("tenant: %s (key: %s)\n", ping.Tenant, ping.KeyName)

	usage, err := client.Usage(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "usage:", err)
		os.Exit(1)
	}
	fmt.Printf("requests: %d (blocked %d), bytes: %d across %d domains\n",
		usage.Requests, usage.Blocked, usage.BytesTotal, len(usage.Domains))

	domains, err := client.Domains(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "domains:", err)
		os.Exit(1)
	}
	for _, d := range domains.Domains {
		fmt.Printf("- %s stage %d (%s) under_attack=%v requests=%d\n",
			d.Name, d.Stage, d.StageName, d.UnderAttack, d.Requests)
	}
}
