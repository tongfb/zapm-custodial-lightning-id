# ZAPM Custodial Lightning ID

ZAPM Custodial Lightning ID is a self-hosted Lightning Address layer for Cloudflare Workers and D1.

It lets you keep a stable Lightning Address on your own domain while using a custodial LNURL-pay wallet or provider as the payment backend. The backend can be changed later from a private admin interface without changing the public Lightning Address.

Example:

`username@yourdomain.com`

## What is included

- `zapm-lnurl.js` — public LNURL-pay gateway Worker
- `zapm-admin.js` — private ZAPM Admin Worker
- `schema.sql` — D1 database schema
- `wrangler-lnurl.jsonc` — public Worker deployment config
- `wrangler-admin.jsonc` — admin Worker deployment config
- `.gitignore` — excludes local secrets and production backups

## 1. Fork and configure your domain

Open `zapm-admin.js` and edit only the deployment-specific CONFIG values near the top:

```js
const CONFIG = Object.freeze({
  PUBLIC_DOMAIN: "yourdomain.com",
  ADMIN_ORIGIN: "https://admin.yourdomain.com",
});
```

`PUBLIC_DOMAIN` is the domain used for Lightning Addresses.

`ADMIN_ORIGIN` is the exact HTTPS origin used for the private ZAPM Admin Worker.

The rest of the ZAPM application logic does not need domain-specific edits.

## 2. Create the D1 database

Create a new Cloudflare D1 database and run `schema.sql` in the D1 Console.

It creates:

- `lightning_ids`
- `audit_log`
- `admin_login_attempts`
- `sessions`

Do not import someone else's production database export into a new fork.

## 3. Deploy the public Worker

The repository includes `wrangler-lnurl.jsonc`.

Deploy command:

```text
npx wrangler deploy --config wrangler-lnurl.jsonc
```

Bind the D1 database to the Worker using binding name:

`DB`

Route the Worker to:

`https://yourdomain.com/.well-known/lnurlp/*`

The public endpoint for a user becomes:

`https://yourdomain.com/.well-known/lnurlp/<username>`

## 4. Deploy the Admin Worker

The repository includes `wrangler-admin.jsonc`.

Deploy command:

```text
npx wrangler deploy --config wrangler-admin.jsonc
```

Bind the same D1 database to the Admin Worker using binding name:

`DB`

Attach the Admin Worker to the exact origin configured in `CONFIG.ADMIN_ORIGIN`.

## 5. Add Admin secrets

Create these Cloudflare Worker secrets on the Admin Worker:

- `ADMIN_PASSWORD`
- `SESSION_SECRET`

Use a long random value for `SESSION_SECRET` and keep it different from the admin password.

Do not put either value in GitHub.

## 6. Add a Lightning ID

Sign in to ZAPM Admin and add:

- username
- optional display name
- a real HTTPS LNURL-pay backend URL from your custodial wallet or provider
- optional private note

ZAPM verifies the backend before saving it.

## 7. Test the public endpoint

For a configured username such as `alice`, open:

`https://yourdomain.com/.well-known/lnurlp/alice`

A working setup should return a valid LNURL-pay `payRequest` response from the configured backend.

Test a small real Lightning payment before treating a new deployment as production-ready.

## Backend policy

ZAPM accepts LNURL-pay backends that:

- use HTTPS
- return a valid `payRequest`
- do not redirect
- respond within the configured timeout
- stay within the configured response-size limit

## Security notes

The Admin Worker uses server-side sessions, Secure/HttpOnly/SameSite cookies, same-origin checks, login rate limiting, and D1-backed session revocation.

Never commit:

- `ADMIN_PASSWORD`
- `SESSION_SECRET`
- production session data
- private production database exports
- wallet credentials or API keys

## License

ZAPM Custodial Lightning ID is released under the MIT License. See `LICENSE` for the full license text.
