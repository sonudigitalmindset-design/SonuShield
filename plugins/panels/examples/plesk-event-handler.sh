#!/bin/sh
# Plesk event-handler sketch (Batch 8).
#
# Install: Plesk > Tools & Settings > Event Manager > Add Event Handler,
# event "Domain created", command this script. Plesk passes event
# parameters as environment variables (e.g. NEW_DOMAIN_NAME); the exact
# names vary by Plesk version — confirm with the Event Manager docs and
# test on a staging domain first. This sketch is UNTESTED against a real
# Plesk installation. See plugins/panels/README.md.
#
# The API secret must be available in the handler environment as
# SONUSHIELD_API_SECRET. Never hard-code it here.

set -eu

DOMAIN="${NEW_DOMAIN_NAME:-${1:-}}"
if [ -z "$DOMAIN" ]; then
    echo "sonushield handler: no domain in event" >&2
    exit 1
fi

PROXY_URL="${SONUSHIELD_PROXY_URL:-https://proxy.example.com}"
CLIENT="${SONUSHIELD_CLIENT:-/usr/local/bin/sonushield_panel.py}"
BACKEND="${SONUSHIELD_BACKEND:-127.0.0.1:8080}"

python3 "$CLIENT" --api-url "$PROXY_URL" add-domain \
    --name "$DOMAIN" --backend "$BACKEND" --scheme http \
    --template standard || echo "sonushield handler: provisioning failed for $DOMAIN" >&2
