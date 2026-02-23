# Asgardeo x Authsignal adapter

Production-ready adapter service that implements Asgardeo Custom Authentication and delegates challenge orchestration to Authsignal.

## What this service does

1. Asgardeo calls `POST /api/authenticate` with a `flowId` and user context.
2. Adapter calls Authsignal Track Action.
3. If challenge is required, adapter returns `INCOMPLETE` with redirect URL.
4. User completes Authsignal challenge and returns to `GET /api/callback`.
5. Adapter validates challenge result with Authsignal Validate API.
6. Adapter stores final outcome and redirects user to Asgardeo resume URL.
7. Asgardeo calls `POST /api/authenticate` again, adapter returns final `SUCCESS` or `FAILED`.

## Requirements

- Node.js 20+
- Redis (required for production, optional for local)

## Environment variables

Use `.env.example` as template.

- `PUBLIC_BASE_URL`: Public URL of this adapter service.
- `CALLBACK_PATH`: Callback path for Authsignal redirect (default `/api/callback`).
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

## Production run (Docker)

```bash
docker build -t asgardeo-authsignal-adapter .
docker run --rm -p 3000:3000 --env-file .env asgardeo-authsignal-adapter
```

## Asgardeo setup checklist

1. Register adapter endpoint `POST /api/authenticate` as custom authenticator service.
2. Configure request authentication (Basic/Bearer/API Key) and match env settings.
3. Add authenticator as a 2FA step in login flow.
4. Ensure callback URL `${PUBLIC_BASE_URL}${CALLBACK_PATH}` is allowed in Authsignal.
5. Configure `ASGARDEO_RESUME_URL_TEMPLATE` with your Asgardeo tenant resume endpoint.

## API behavior

`POST /api/authenticate` response contract:

- `{"actionStatus":"SUCCESS"}`
- `{"actionStatus":"FAILED","failureReason":"..."}`
- `{"actionStatus":"INCOMPLETE","authData":{"additionalData":{"redirectUrl":"..."}}}`
- `{"actionStatus":"ERROR","failureReason":"..."}`
