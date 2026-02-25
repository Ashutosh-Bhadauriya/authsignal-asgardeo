# Asgardeo x Authsignal adapter

Production-ready adapter service that implements Asgardeo Custom Authentication and delegates challenge orchestration to Authsignal.

## What this service does

1. Asgardeo calls `POST /api/authenticate` with a `flowId` and user context.
2. Adapter calls Authsignal Track Action.
3. If challenge is required, adapter returns `INCOMPLETE` with Authsignal redirect URL.
4. User completes Authsignal challenge and is redirected to Asgardeo resume URL.
5. Asgardeo calls `POST /api/authenticate` again, adapter checks challenge result via Authsignal Get Action API.
6. Adapter returns final `SUCCESS` or `FAILED`.

## Requirements

- Node.js 20+
- Redis (required for production, optional for local)

## Environment variables

Use `.env.example` as template.

- `ASGARDEO_RESUME_URL_TEMPLATE`: Asgardeo resume URL template, must include `{flowId}`.
- `ASGARDEO_AUTH_MODE`: `none` | `basic` | `bearer` | `api-key`.
- `AUTHSIGNAL_API_URL`: Authsignal Server API base URL (`https://api.authsignal.com` or region equivalent).
- `AUTHSIGNAL_SECRET`: Authsignal secret key.
- `STORE_DRIVER`: `memory` or `redis` (`redis` for production).
- `FLOW_TTL_SECONDS`: Flow state TTL.

## Asgardeo resume URL template

Set `ASGARDEO_RESUME_URL_TEMPLATE` to the Asgardeo endpoint that resumes custom auth flow.

Example:

```bash
ASGARDEO_RESUME_URL_TEMPLATE=https://api.asgardeo.io/t/{tenant}/logincontext?flowId={flowId}
```

`{tenant}` is optional. If your tenant is fixed, use a static URL and keep only `{flowId}`.

## Local development

```bash
npm install
cp .env.example .env
npm run dev
```

## Test and typecheck

```bash
npm run check
```

## Asgardeo setup checklist

1. Register adapter endpoint `POST /api/authenticate` as custom authenticator service.
2. Configure request authentication (Basic/Bearer/API Key) and match env settings.
3. Add authenticator as a 2FA step in login flow.
4. Configure `ASGARDEO_RESUME_URL_TEMPLATE` with your Asgardeo tenant resume endpoint.
5. Set the Asgardeo resume URL as the redirect URL in your Authsignal action configuration.
