#!/bin/sh
# cPanel/WHM postwwwacct hook sketch (Batch 8).
#
# Install (WHM): place in /usr/local/cpanel/hooks/ via the Hook Manager,
# or register with `manage_hooks`. This sketch is UNTESTED against a real
# WHM installation: hook argument passing varies by version. Adapt and
# test on a staging account first. See plugins/panels/README.md.
#
# Expected inputs from the hook environment (WHM passes account data):
#   $1 = domain (adapt to the hook's actual argument format)
# Backend mapping below assumes the site listens on 127.0.0.1:8080 plus
# one port per account; replace with the server's real layout.
#
# The API secret must be available in the hook environment as
# SONUSHIELD_API_SECRET. Never hard-code it here.

set -eu

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
    echo "sonushield hook: no domain argument" >&2
    exit 1
fi

PROXY_URL="${SONUSHIELD_PROXY_URL:-https://proxy.example.com}"
CLIENT="${SONUSHIELD_CLIENT:-/usr/local/bin/sonushield_panel.py}"

# Backend: adapt to the server's layout. This sketch uses a fixed
# origin port; a real hook derives it from the account's vhost.
BACKEND="${SONUSHIELD_BACKEND:-127.0.0.1:8080}"

# Certificate paths: adapt to where the panel stores the domain's
# certificate. AutoSSL paths vary; confirm before use.
CERT="/etc/ssl/certs/${DOMAIN}.crt"
KEY="/etc/ssl/private/${DOMAIN}.key"

ARGS="--api-url $PROXY_URL add-domain --name $DOMAIN --backend $BACKEND --scheme http --template standard"
if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    ARGS="$ARGS --certificate $CERT --key $KEY"
fi

# shellcheck disable=SC2086
python3 "$CLIENT" $ARGS || echo "sonushield hook: provisioning failed for $DOMAIN" >&2
