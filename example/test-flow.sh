#!/bin/sh
set -e

# Wait for services to be ready
echo "Waiting for ingress-proxy to be ready..."
until curl -s http://ingress-proxy/.well-known/openid-configuration > /dev/null; do
  sleep 1
done

echo ""
echo "--- 1. Fetching OIDC Configuration ---"
curl -s http://ingress-proxy/.well-known/openid-configuration | jq .

echo ""
echo "--- 2. Performing M2M Token Exchange (Client Credentials) ---"
curl -s -X POST http://ingress-proxy/token \
     -H 'Content-Type: application/json' \
     -d '{"grant_type": "client_credentials", "client_id": "example-client", "client_secret": "example-secret"}' | jq .

echo ""
echo "--- 3. Performing Authorization Code Flow ---"
echo "a. Requesting Authorization Code..."
# The -I flag gets headers, grep/sed extracts the code from the Location redirect
LOCATION=$(curl -s -I "http://ingress-proxy/authorize?client_id=example-app&response_type=code&redirect_uri=http://localhost/callback&code_challenge=xyz")
CODE=$(echo "$LOCATION" | grep -i location | sed -n 's/.*code=\([^& ]*\).*/\1/p' | tr -d '\r')

echo "b. Received Code: $CODE"

echo "c. Exchanging Code for Tokens..."
curl -s -X POST http://ingress-proxy/token \
     -H 'Content-Type: application/json' \
     -d "{\"grant_type\": \"authorization_code\", \"client_id\": \"example-app\", \"code\": \"$CODE\"}" | jq .

echo ""
echo "--- Flow Complete ---"
