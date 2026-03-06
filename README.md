# IRS Financial Calculator

A professional, self-hosted web application for IRS tax resolution analysis. Helps tax professionals estimate a client's ability to pay IRS tax debts using official IRS Collection Financial Standards — with live data pulled directly from irs.gov.

---

## Screenshots

<!-- Add screenshots to the /screenshots directory and update paths here -->

| Login | Calculator | Admin Dashboard |
|---|---|---|
| ![Login](screenshots/01-login.png) | ![Calculator](screenshots/02-calculator.png) | ![Admin](screenshots/07-admin-analytics.png) |

| Invoice Builder | User Management | Database Viewer |
|---|---|---|
| ![Invoice](screenshots/06-invoice-builder.png) | ![Users](screenshots/08-admin-users.png) | ![DB](screenshots/10-admin-dbviewer.png) |

---

## Features

### IRS Financial Calculator
- Multi-tab analysis: Income → Expenses → Assets → Results
- IRS Collection Financial Standards auto-updated from irs.gov (National + Local)
- ZIP code → county/MSA lookup for accurate local transportation standards
- Live IRS underpayment interest rate (quarterly, fetched from irs.gov)
- Payment option estimates: Installment Agreement, PPIA, Offer in Compromise
- Print-ready results report

### Multi-User System
- Role-based access: **Admin** and **User** roles
- Secure login with optional **TOTP 2FA**
- Per-session JWT tokens stored server-side (revocable)
- Automatic account lockout on failed login attempts

### Client Case Management
- Create and manage client cases linked to tax analyses
- Per-case notes (with pin support) and file attachments
- Save full calculator analysis snapshots to a case
- Cases persist in the database for future reference

### Invoicing & Email
- Create branded invoices with live preview
- Per-invoice customization: logo (upload or URL), accent color, business info
- Line items with quantity, unit price, tax toggle
- Send invoices via email (HTML formatted)
- Free-form email composer with SMTP/IMAP configuration per user
- Full sent email log

### Admin Dashboard
- **Analytics** — login charts, user activity, case totals, security alerts
- **User Management** — create/edit/disable users, reset passwords, force logout
- **Active Sessions** — view and revoke any live session
- **Audit Log** — every action logged with timestamp, IP, and user
- **Usage Reports** — per-user activity reports, exportable to CSV
- **Database Viewer** — browse, search, and edit all database tables

### Security
- All passwords hashed with bcrypt (configurable work factor)
- JWT secrets loaded from environment variables only
- CORS restricted to configured origins
- Helmet.js security headers
- Rate limiting on authentication endpoints
- Non-root container user
- SQLite WAL mode for reliability

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Vanilla HTML/CSS/JS, Tailwind CSS |
| Backend | Node.js 18, Express 4 |
| Database | SQLite 3 (WAL mode) |
| Auth | JWT + bcrypt + speakeasy (TOTP) |
| Email | Nodemailer (SMTP) |
| Proxy | nginx:alpine |
| Container | Docker + Docker Compose |

---

## Quick Start — Docker

### Prerequisites
- Docker Desktop or Docker Engine + Compose plugin
- Git

### 1. Clone & Configure

```bash
git clone https://github.com/YOUR_USERNAME/irs-financial-calculator.git
cd irs-financial-calculator

cp .env.example .env
```

Edit `.env` and set at minimum:

```env
# Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
JWT_SECRET=your_64_char_random_secret_here

# Password for the first admin account (created on first startup)
DEFAULT_ADMIN_PASSWORD=YourSecurePassword!
```

### 2. Build & Run

```bash
docker compose up -d --build
```

### 3. Access

Open `http://localhost` in your browser.

**First login:**
- Username: `admin`
- Password: whatever you set as `DEFAULT_ADMIN_PASSWORD`

> **Change the admin password immediately after first login.**

---

## QNAP Container Station Deployment

Tested on **Container Station 3.1.2.1742 (2025/11/26)**.

### Step-by-Step

**1.** Open **Container Station** in QNAP App Center

**2.** Go to **Applications** → **Create**

**3.** Paste the contents of `docker-compose.qnap.yml` into the YAML editor

**4.** Edit the three required values:

```yaml
# Generate at: https://generate-secret.vercel.app/64
JWT_SECRET: "YOUR_64_CHAR_SECRET"

# Your QNAP's IP address
CORS_ORIGINS: "http://YOUR_QNAP_IP:8880"

# First admin password
DEFAULT_ADMIN_PASSWORD: "YourSecurePassword!"
```

**5.** Click **Deploy**

**6.** Wait ~60 seconds for both containers to start

**7.** Access the app at `http://YOUR_QNAP_IP:8880`

### QNAP Notes

- Port `8880` is used by default — change it in the YAML if already taken
- The database is stored in a Docker named volume (`irs-db`) and persists across restarts
- To update: Container Station → Applications → your app → **Pull & Restart**

### Troubleshooting QNAP

If the frontend container keeps restarting, check logs:

```bash
# SSH into QNAP
ssh admin@YOUR_QNAP_IP

export DOCKER_HOST=unix:///var/run/docker.sock
CS=/share/CACHEDEV1_DATA/.qpkg/container-station
export PATH=$CS/bin:$CS/usr/bin:$PATH

docker logs irs-frontend --tail 20
```

**Common issue:** nginx cannot resolve the backend container name at startup.

**Fix:** The nginx config uses Docker's embedded DNS resolver (`127.0.0.11`) with a variable upstream so nginx does not fail on startup if the backend container name is not immediately resolvable.

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `JWT_SECRET` | ✅ | — | JWT signing secret (min 32 chars) |
| `DEFAULT_ADMIN_PASSWORD` | — | `ChangeMe@First!` | Password for seeded admin account |
| `JWT_EXPIRY` | — | `8h` | Token expiry duration |
| `BCRYPT_ROUNDS` | — | `12` | bcrypt work factor (10–14 recommended) |
| `DB_PATH` | — | `/data/users.db` | SQLite database path |
| `CORS_ORIGINS` | — | `http://localhost` | Comma-separated allowed origins |
| `HTTP_PORT` | — | `80` | Host port for nginx |
| `FACEBOOK_APP_ID` | — | — | Facebook Graph API App ID (optional) |
| `FACEBOOK_APP_SECRET` | — | — | Facebook App Secret (optional) |
| `FACEBOOK_GROUP_ID` | — | — | Facebook Group ID (optional) |

---

## Project Structure

```
irs-financial-calculator/
├── backend/
│   ├── server.js          # Express API — all routes
│   ├── package.json
│   ├── Dockerfile
│   └── .dockerignore
├── screenshots/           # App screenshots (add your own)
├── login.html             # Login page (entry point)
├── app.html               # IRS Financial Calculator
├── admin.html             # Admin dashboard
├── invoices.html          # Invoicing & email
├── nginx.conf             # nginx reverse proxy config
├── Dockerfile.nginx       # nginx image with pages baked in
├── docker-compose.yml     # Standard Docker deployment
├── docker-compose.qnap.yml # QNAP Container Station deployment
├── .env.example           # Environment variable template
└── .gitignore
```

---

## Database Schema

| Table | Purpose |
|---|---|
| `users` | Accounts, roles, login tracking, 2FA |
| `sessions` | Active JWT tokens (revocable) |
| `audit_log` | Every action: logins, creates, edits, deletes |
| `client_cases` | Client tax resolution cases |
| `case_notes` | Notes per case |
| `case_files` | File metadata per case |
| `email_settings` | SMTP/IMAP config + business branding per user |
| `invoices` | Invoice records with full financials |
| `invoice_items` | Line items per invoice |
| `email_log` | Outgoing email history |

---

## IRS Standards — Automatic Updates

The app fetches current IRS Collection Financial Standards directly from irs.gov on every page load:

- **National Standards** (food, clothing, healthcare) — fetched and parsed from irs.gov HTML
- **Local Transportation Standards** — by Census region and MSA
- **Quarterly Interest Rate** — fetched from irs.gov/payments/quarterly-interest-rates
- **ZIP code → MSA lookup** — via zippopotam.us (free, no API key)

Standards are cached in `localStorage` for 7 days (interest rate: 24 hours). A "↻ Refresh Rates" button forces an immediate re-fetch. If all fetches fail, built-in fallback values (verified April 2025, current through June 2026) are used.

---

## License

MIT — see [LICENSE](LICENSE)
