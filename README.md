# Phoenix Codex - Backend API 🚀 DEMO

This is the core REST API for the **Phoenix Codex** e-commerce platform. It handles data persistence, administrative functions, and secure communication between the frontend and the database.

## 🛡️ Security Implementations
- **CORS Policy**: Restricts API access to authorized frontend domains only.
- **Rate Limiting**: Prevents abuse on sensitive endpoints (Login, Vote, Newsletter).
- **Data Protection**: Sensitive information is managed via Environment Variables.
- **Helmet.js**: Secured HTTP headers to prevent common web vulnerabilities.

## 🛠️ Tech Stack
- **Node.js & Express**: High-performance backend routing.
- **MongoDB & Mongoose**: Scalable NoSQL database management.
- **Bcrypt**: Industrial-grade password hashing.
- **JWT**: Short-lived scoped tokens for user and admin sessions, revocable via `tokenVersion`.
- **Mailjet Send API**: Transactional email over HTTPS. Render's free tier blocks outbound SMTP
  (ports 25/465/587), so SMTP-based delivery cannot work from this host.

## ⚙️ Installation & Setup
1. Clone the repository.
2. Run `npm install`.
3. Copy `.env.example` to `.env` and fill it in. Every variable is documented there; `DB_URI`,
   `JWT_SECRET` and `ADMIN_PASSWORD` are required or the authenticated routes refuse to work.
4. Start the server using `node server.js`.

## 👷 Development Workflow
Same Git Flow as the frontend: development and testing happen on `main-test`, merged into `main`
via pull request. Render auto-deploys from `main` only, so `main-test` is the safety net — a push
there never touches production.

## 🚢 Deploy order
The API and the storefront are separate repositories with independent deploys, and a single
feature often touches both. **Always deploy this repository first**, wait for Render to report
*Live*, and only then merge the frontend PR.

Backend changes are additive (a new route, a new field), so an older frontend keeps working
against a newer API. The reverse does not: a frontend that ships first calls routes that do not
exist yet and fails in production.

> Render's free instance spins down when idle, so the first request after a deploy can take 50+
> seconds. Wake it with one request before concluding a deploy is broken.

---
*Developed as part of the Phoenix Codex Project.*
