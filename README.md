# MERN Authentication

MongoDB + Express + React + Node app with **registration, login, logout, protected functionality (personal notes) and input validation**.

## Run

```bash
cd server && cp .env.example .env     # set JWT_SECRET and MONGODB_URI
npm install && npm run dev            # API on :5000

cd client && npm install && npm run dev   # app on http://localhost:5173
```

Optional: put your email in `ADMIN_EMAIL` in `.env` before registering to get the `admin` role (unlocks the admin-only Users page).

## How it works

- **Registration** `POST /api/auth/register` – validates name/email/password, hashes the password with bcrypt (cost 12), saves the user, logs them in.
- **Login** `POST /api/auth/login` – compares the password to the hash, then sets a signed JWT (1 h) in an `httpOnly`, `sameSite=strict` cookie. Failures always return the same generic message; login/register are rate limited.
- **Logout** `POST /api/auth/logout` – clears the cookie.
- **Protected functionality** `/api/notes` – `requireAuth` middleware rejects requests without a valid token (401). React's `ProtectedRoute` redirects logged-out visitors to `/login`.
- **Input validation** – express-validator on the server (types, lengths, email format, password strength, Mongo ids, unknown fields dropped) plus matching checks in the React forms. `sanitizeFilter` blocks NoSQL injection.
- **Secrets** – `JWT_SECRET` and `MONGODB_URI` come from `.env`, which is git-ignored.

## Authentication vs. Authorization

**Authentication** answers *"Who are you?"* It proves identity. In this app it happens when you register or log in: the server checks your email and password (against the bcrypt hash) and, if they match, issues a signed token. On every later request `requireAuth` verifies that token. A failure means **401 Unauthorized** (we do not know who you are).

**Authorization** answers *"What are you allowed to do?"* It happens after authentication and decides which resources and actions an identified user may access. In this app:
- Notes are filtered by `owner`, so one user can never read, edit or delete another user's notes.
- `requireRole('admin')` protects `/api/admin/users`; a regular user who is logged in gets **403 Forbidden** (we know who you are, but you are not permitted).

In short: authentication verifies identity; authorization controls permissions. You must be authenticated before authorization can be applied, but being authenticated does not mean you are authorized for everything. Example: a hotel key card proves you are a guest (authentication), but it only opens your own room (authorization).

## Submission checklist
1. GitHub repository URL
2. Source files (this repo; never commit `.env`)
3. Screenshot of the GitHub repository
4. Screenshot of a committed file, e.g. `server/server.js`
