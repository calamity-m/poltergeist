# Project Specification: OIDC "Ghost" Shim - Poltergeist

## 1. Project Overview

A lightweight, stateless OIDC Identity Provider written in Rust. Its primary purpose is to bridge an existing Upstream Identity Provider (acting via Ingress headers) to downstream applications (Camunda) that require strict OIDC compliance.

It does not manage users. It creates "Ghost" sessions based on trusted headers or upstream tokens, re-signing them into a format the downstream application expects.

## 2. Technology Stack

### Core Runtime

tokio: The async runtime (required).

axum: The web framework for high-performance, ergonomic routing (required).

### Identity & Crypto

jsonwebtoken: For decoding upstream JWTs (validation) and encoding downstream JWTs (signing). Essential for handling the header payload manipulation.

rsa: To handle loading the PKCS#8 / PEM private keys from the Kubernetes secret for signing tokens.

sha2 / base64: For calculating PKCE challenges (S256) and thumbprints.

### Utilities

reqwest: (Optional) If you need to fetch the upstream IdP's JWKS to validate the incoming header token strictly.

dashmap or moka: For thread-safe, high-performance in-memory storage of authorization codes (short-lived state). moka provides automatic TTL (time-to-live) eviction, which is perfect for auth codes.

serde / serde_json: For robust JSON handling of OIDC payloads.

config: To handle the runtime configuration (upstream issuers, allowed clients) via layered YAML/Environment variables.

tracing / tracing-subscriber: For structured logging (essential for debugging auth flows).

### 3. Architecture & Flows

#### A. The Browser Flow (User Login)

Goal: Authenticate a human user accessing Camunda Web UI.

Incoming Request: User hits GET /authorize.

Header Check: Middleware checks for Authorization: Bearer <Upstream_JWT>.

Branch A (Authenticated):

Validate: Verify <Upstream_JWT> against Upstream Issuer (signature + expiry).

Extract: Pull user email/sub from the upstream token.

Store Code: Generate a random auth_code. Store it in the Dashmap/Moka cache mapped to the user identity + original code_challenge (PKCE) + nonce.

Redirect: Return 302 Found to redirect_uri?code=<auth_code>&state=<state>.

Branch B (Unauthenticated):

Redirect: Return 302 Found to the Upstream IdP's login page.

Note: The Upstream IdP will authenticate the user and redirect them back to the original URL (your /authorize endpoint), this time with the headers injected by the Ingress.

#### B. The Token Exchange (Browser / Public Client)

Goal: Camunda frontend swaps the code for a token.

Incoming Request: POST /token (grant_type=authorization_code).

PKCE Validation: Verify the incoming code_verifier against the stored code_challenge (SHA256).

Minting:

Retrieve the user identity from the cache using the code.

Create a ID Token and Access Token.

Sign: Sign both using the Shim's Private Key (loaded from K8s).

Response: Return standard OIDC JSON.

#### C. The M2M Flow (Service Accounts)

Goal: Backend services (Zeebe workers) authenticate.

Incoming Request: POST /token (grant_type=client_credentials).

Auth Check: Validate client_id and client_secret against the static configuration (loaded at startup).

Minting:

Create a token with sub: <client_id>.

Inject configured scopes/groups for that client.

Sign: Sign using the Shim's Private Key.

Response: Return Access Token.

### 4. Configuration Structure (config.yaml)

The application should ingest a configuration that defines the "Ghost" clients and the upstream trust.

```YAML
server:
  port: 8080
  base_url: "https://auth.internal.corp" # Your Shim's URL

upstream:
  issuer: "https://accounts.google.com" # Or your corporate IdP
  jwks_url: "https://www.googleapis.com/oauth2/v3/certs"

#### Static keys loaded from K8s secrets (via Env vars usually, but mapped here)
signing:
  private_key_path: "/etc/secrets/key.pem"
  kid: "shim-key-01"

clients:
  #### Browser Client (Camunda Web)
  - client_id: "camunda-web"
    type: "public"
    redirect_uris:
      - "https://camunda.internal.corp/identity/callback"
    
  #### M2M Client (Zeebe Worker)
  - client_id: "zeebe-worker-01"
    type: "private"
    client_secret: "env(ZEEBE_CLIENT_SECRET)" # Load from Env
    permissions: ["zeebe:read", "zeebe:write"]
```

## 5. API Endpoints Specification

### 1. Discovery

GET /.well-known/openid-configuration

Returns static JSON pointing to your shim's endpoints (/authorize, /token, /jwks).

### 2. JSON Web Key Set (JWKS)

GET /jwks

Returns the Public Key part of your RSA key pair. Camunda uses this to verify the tokens you issued.

### 3. Authorization (Browser)

GET /authorize

Query Params: response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method.

Logic: The "Air Traffic Controller". Checks headers vs Upstream, generates Code, redirects.

### 4. Token Issuance

POST /token

Form Params: grant_type, code, redirect_uri, client_id, client_secret, code_verifier.

Logic: Handles both authorization_code (PKCE verified) and client_credentials (Secret verified).

### 6. Implementation Strategy

#### Phase 1: The "Hollow" 

Set up axum router.

Implement /.well-known/openid-configuration to return hardcoded paths.

Generate an RSA Keypair (openssl genrsa -out private.pem 2048).

Implement /jwks to serve the public key derived from that PEM.

#### Phase 2: The M2M Flow (Easiest)

Implement /token handler.

Add logic for grant_type="client_credentials".

Validate static secret.

Mint and sign a JWT.

Test: Use curl to get a token, then verify it against your /jwks using jwt.io or a verifier script.

#### Phase 3: The Browser Flow

Implement /authorize.

Add logic to look for Authorization header.

Add logic to redirect to Upstream IdP if header is missing.

Implement the "Code Storage" (using moka or Dashmap).

Update /token to handle grant_type="authorization_code" and verify PKCE.

#### Phase 4: Productionize

Load upstream JWKS (to actually validate the incoming header, not just trust it blindly).

Dockerize (cargo build --release).

Mount K8s secrets.