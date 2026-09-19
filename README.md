# Auth Service

A complete, reusable authentication backend built with Node.js, Express, and MongoDB — designed to be dropped into any frontend or app that needs production-grade auth, without rebuilding it from scratch each time.

## Features

- **Local authentication** — signup/login with bcrypt password hashing, account lockout after repeated failed attempts
- **JWT access tokens + rotating refresh tokens** — short-lived stateless access tokens, long-lived refresh tokens stored server-side with automatic rotation and **theft detection** (a replayed, already-rotated token triggers revocation of the entire session chain)
- **Multi-device sessions** — each login starts an independent session; logging out or revoking one device never affects others
- **Email verification** — signup triggers a verification email; resend endpoint is rate-limited with an atomic daily cap
- **Password reset & change** — "forgot password" flow with no email-enumeration leak, plus an authenticated "change password" flow; both revoke all existing sessions on success
- **Two-Factor Authentication (TOTP)** — Google Authenticator–compatible, with one-time backup recovery codes
- **Google OAuth** — safe account linking (only auto-links to an existing local account when Google confirms the email is verified)
- **Rate limiting** — per-route limits on login, signup, password reset, resend, and 2FA verification, plus a global baseline
- **Input validation** — Zod schemas on every route, returning clean, field-specific error messages
- **Security hardening** — `helmet`, `cors` with credentialed cookies, NoSQL-injection sanitization, HTTP parameter pollution protection

## Tech Stack

| Layer | Choice |
|---|---|
| Runtime | Node.js (ESM) |
| Framework | Express |
| Database | MongoDB + Mongoose |
| Auth tokens | `jsonwebtoken` (access), random bytes + SHA-256 hash (refresh) |
| Password hashing | `bcrypt` |
| 2FA | `otplib` (TOTP) + `qrcode` |
| OAuth | `passport` + `passport-google-oauth20` |
| Validation | `zod` |
| Email | `nodemailer` (SMTP — Mailtrap for dev, any SMTP provider in production) |
| Rate limiting | `express-rate-limit` |
| Security headers | `helmet`, `cors`, `express-mongo-sanitize`, `hpp` |

## Project Structure

```
auth-service/
├── src/
│   ├── config/
│   │   ├── db.js            # MongoDB connection
│   │   ├── env.js           # Zod-validated environment variables
│   │   └── passport.js      # Google OAuth strategy
│   ├── controllers/
│   │   └── auth.controller.js
│   ├── middlewares/
│   │   ├── auth.middleware.js   # verifies access tokens, attaches req.userId
│   │   ├── rateLimiter.js
│   │   └── validate.js          # Zod request-body validation
│   ├── models/
│   │   ├── User.js
│   │   └── RefreshToken.js
│   ├── routes/
│   │   └── auth.routes.js
│   ├── services/
│   │   ├── token.service.js     # access/refresh token issuing & rotation
│   │   ├── email.service.js     # nodemailer wrapper
│   │   └── otp.service.js
│   ├── utils/
│   │   └── generateUsername.js
│   ├── validations/
│   │   └── auth.validation.js
│   └── app.js
├── server.js
├── .env.example
└── package.json
```

## Setup

```bash
git clone <this-repo-url>
cd auth-service
npm install
```

Copy `.env.example` to `.env` and fill in real values (see table below). Then:

```bash
npm run dev
```

Server boots on `PORT` (default `3000`). It will refuse to start if any required environment variable is missing or malformed — this is deliberate, fail-fast validation via Zod in `config/env.js`.

## Environment Variables

| Variable | Description |
|---|---|
| `PORT` | Port the backend runs on |
| `CLIENT_URL` | Base URL of the frontend consuming this API (used for CORS, email links, and OAuth redirects) |
| `MONGO_URI` | MongoDB connection string |
| `JWT_ACCESS_SECRET` | Signing secret for short-lived access tokens (32+ chars) |
| `JWT_ACCESS_EXPIRY` | e.g. `15m` |
| `JWT_REFRESH_EXPIRY` | e.g. `30d` — refresh tokens are random bytes, not JWTs, but this controls their DB expiry |
| `JWT_TWO_FACTOR_SECRET` | Separate signing secret for the short-lived "passed password, pending 2FA" token |
| `NODE_ENV` | `development` / `production` — controls cookie `secure` flag automatically |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `EMAIL_FROM` | SMTP credentials (Mailtrap sandbox for dev) |
| `EMAIL_VERIFICATION_EXPIRY` | e.g. `24h` |
| `PASSWORD_RESET_EXPIRY` | e.g. `15m` |
| `APP_NAME` | Shown as the issuer name inside authenticator apps for 2FA |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_CALLBACK_URL` | From Google Cloud Console OAuth credentials |

## API Reference

All routes are prefixed with `/api/auth`. Cookies (`refreshToken`) are httpOnly and set automatically by the relevant endpoints — nothing to configure client-side beyond sending requests with `credentials: "include"`.

### Local Auth

| Method & Path | Auth required | Body | Notes |
|---|---|---|---|
| `POST /signup` | No | `name, email, password, dob?` | Creates account, sends verification email, returns tokens immediately |
| `POST /login` | No | `email, password` | Returns tokens directly, **or** `{ requires2FA: true, twoFactorToken }` if 2FA is enabled on the account |
| `POST /refresh` | Refresh cookie | — | Rotates the refresh token, returns a new access token |
| `POST /logout` | Refresh cookie | — | Revokes the current session only (not other devices) |
| `GET /getme` | Bearer access token | — | Returns the current user's profile |

### Email Verification

| Method & Path | Auth required | Body | Notes |
|---|---|---|---|
| `POST /verify-email/:token` | No | — | Token comes from the emailed link |
| `POST /resend` | Bearer access token | — | Rate-limited (IP) + atomic daily cap of 5/account |

### Password Management

| Method & Path | Auth required | Body | Notes |
|---|---|---|---|
| `POST /forget-password` | No | `email` | Always returns the same generic message, regardless of whether the email exists (prevents enumeration) |
| `POST /reset-password/:rawPassResetToken` | No | `newPassword` | Revokes **all** existing sessions on success |
| `POST /change-password` | Bearer access token | `currentPassword, newPassword` | Revokes all existing sessions on success |

### Two-Factor Authentication

| Method & Path | Auth required | Body | Notes |
|---|---|---|---|
| `POST /2fa/setup` | Bearer access token | — | Returns `{ secret, qrCodeDataUrl }`; 2FA is not yet enabled at this point |
| `POST /2fa/verify-setup` | Bearer access token | `token` (6-digit code) | Confirms setup, enables 2FA, returns 8 one-time backup codes (shown only once) |
| `POST /2fa/verify-login` | No (uses `twoFactorToken` from `/login`) | `twoFactorToken, code` | `code` can be a live TOTP code **or** an unused backup code |
| `POST /2fa/regenerate-backup-codes` | Bearer access token | `currentPassword` | Invalidates all previous backup codes |
| `POST /2fa/disable-2fa` | Bearer access token | `currentPassword` | Turns 2FA off entirely |

### Google OAuth

| Method & Path | Notes |
|---|---|
| `GET /google` | Redirect the browser here directly (not a `fetch` call) to start the flow |
| `GET /google/callback` | Google redirects here automatically; server sets the refresh cookie and redirects to `${CLIENT_URL}/oauth/success` |

**Frontend integration note:** since the OAuth callback is a browser redirect (not a JSON response), the frontend's `/oauth/success` page should call `POST /refresh` followed by `GET /getme` on mount to complete the login — the same bootstrap pattern used for page reloads.

## Security Design Notes

- **Refresh token rotation with theft detection**: every refresh token belongs to a `family` (one per login). Reusing an already-rotated token is treated as evidence of theft and revokes the entire family, not just that token.
- **No password/secret is ever stored in plaintext** — passwords use bcrypt; refresh tokens, verification tokens, and password-reset tokens are SHA-256 hashed; only the raw value ever sent to the client.
- **Passwords are optional at the schema level** for OAuth-only accounts, but required for local signup.
- **Google account linking only occurs when Google confirms `email_verified: true`**, preventing account-hijacking via an unverified email claim.
- **Every enumeration-sensitive endpoint** (login, forgot-password) returns identical responses whether or not the account exists.

## Known Limitations / Not Yet Built

- GitHub OAuth (pattern is proven via Google; not implemented)
- Email-based OTP as a 2FA alternative (TOTP only, for now)
- "Log out of all devices" endpoint
- Username/handle system (intentionally deferred — schema is ready if needed later)

## License

MIT
