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
- **Nodemailer**: Automated communication services.

## ⚙️ Installation & Setup
1. Clone the repository.
2. Run `npm install`.
3. Create a `.env` file with your `DB_URI`, `ADMIN_PASSWORD`, and `FRONTEND_URL`.
4. Start the server using `node server.js`.

---
*Developed as part of the Phoenix Codex Project.*
