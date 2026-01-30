# Project Specification: Poltergeist
**The "Performative" OIDC Shim for Camunda 8**

## WARNING
you MUST ALWAYS commit your changes, ensuring your commit
starts with [vibed] so that your commits are immediately identifiable.

## 1. Project Overview
**Ghosted** is a lightweight, stateless OIDC stub written in Rust. It exists solely to satisfy Camunda 8's strict OIDC requirements by bridging an existing Ingress authentication context.

* **The Problem:** Camunda requires an OIDC Provider (Issuer, Token, JWKS). The corporate Identity Provider refuses to support public clients or the specific claims Camunda needs.
* **The Reality:** All traffic arrives via an Ingress Gateway. Requests are *already* authenticated. The Ingress injects the upstream JWT into the `Authorization` header.
* **The Solution:** Ghosted acts as a "Yes Man." It accepts the upstream header, pretends to perform an OIDC login flow (to satisfy the Camunda SPA), and re-signs the upstream identity into a format Camunda accepts.

---

## 2. Technology Stack

* **Language:** Rust
* **Web Framework:** `axum` (Ergonomic, fast, heavily used in Rust ecosystem)
* **Runtime:** `tokio` (The standard async runtime)
* **JWT Handling:** `jsonwebtoken` (For decoding upstream and signing downstream tokens)
* **Key Handling:** `rsa` (To load the signing key)
* **Serialization:** `serde` & `serde_json`
* **State:** `moka` (High-performance caching with TTL for the auth codes)

---

## 3. The "Performative" Auth Flow (Browser)

This flow is designed to unblock the SPA. It does not perform actual user authentication (the Ingress did that).

### Step 1: The "Login" Request
* **Endpoint:** `GET /authorize`
* **Input:** `client_id`, `redirect_uri`, `response_type=code`, `code_challenge` (PKCE garbage).
* **Logic:**
    1.  **Check Header:** Look for `Authorization: Bearer <Upstream_Token>`.
        * *If missing:* Redirect (`302`) to the Upstream IdP Login URL (Ingress handles the rest).
    2.  **Extract Identity:** Decode the upstream token (ignoring signature if internal, or validating against JWKS if strict). Extract `sub` (username), `email`, and `groups`.
    3.  **Generate Code:** Create a random alphanumeric string (`auth_code`).
    4.  **Store State:** Save `auth_code` -> `User Identity Payload` in the `moka` cache (TTL: 30 seconds).
        * *Simplification:* We **ignore** the `code_challenge`. We don't bother storing it.
    5.  **Redirect:** Return `302 Found` to `<redirect_uri>?code=<auth_code>`.

### Step 2: The Token Exchange
* **Endpoint:** `POST /token`
* **Input:** `grant_type=authorization_code`, `code`, `code_verifier` (PKCE garbage), `client_id`.
* **Logic:**
    1.  **Retrieve:** Lookup the `auth_code` in the `moka` cache.
        * *If found:* We get the `User Identity Payload`.
        * *If missing:* Return 400 Bad Request.
    2.  **Ignore PKCE:** We accept the `code_verifier` parameter so the request doesn't fail parsing, but we **do nothing** with it. We trust the code because we just issued it based on a trusted header.
    3.  **Mint Token:**
        * Create a new **ID Token** & **Access Token**.
        * **Issuer:** `http://ghosted-service`
        * **Audience:** `camunda-web`
        * **Claims:** Map the stored `User Identity` to the specific claims Camunda expects (e.g., `groups: ["camunda-admin"]`).
    4.  **Sign:** Sign the tokens with the **Ghosted Private Key** (RSA256).
    5.  **Respond:** Return standard JSON (`access_token`, `id_token`, `expires_in`).

---

## 4. The M2M Flow (Service Accounts)

This handles Zeebe workers or backend scripts that don't have a user context.

* **Endpoint:** `POST /token`
* **Input:** `grant_type=client_credentials`, `client_id`, `client_secret`.
* **Logic:**
    1.  **Validate:** Check `client_id` and `client_secret` against the internal static config (e.g., loaded from `config.yaml` or Env Vars).
    2.  **Mint Token:**
        * Create a token for the machine user.
        * **Subject:** `<client_id>`
        * **Permissions:** Inject capabilities defined in config.
    3.  **Sign & Respond.**

---

## 5. API Contract

### `GET /.well-known/openid-configuration`
Returns the static map so Camunda knows where to look.
```json
{
  "issuer": "http://ghosted:8080",
  "authorization_endpoint": "http://ghosted:8080/authorize",
  "token_endpoint": "http://ghosted:8080/token",
  "jwks_uri": "http://ghosted:8080/jwks",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}