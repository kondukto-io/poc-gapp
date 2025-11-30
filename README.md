# Single Tenant Github Auth POC

Central authentication service with multiple tenant support using GitHub OAuth and GitHub App.

## Architecture

```
┌─────────────────────┐
│  Tenant A (:3001)   │───┐
└─────────────────────┘   │     ┌─────────────────────┐     ┌─────────────┐
                          ├────▶│ Auth Service (:3000)│────▶│   GitHub    │
┌─────────────────────┐   │     └─────────────────────┘     └─────────────┘
│  Tenant B (:3002)   │───┘
└─────────────────────┘
```

## Directory Structure

```
poc-app/
├── auth-service/
│   └── main.go
├── tenant-service/
│   └── main.go
└── README.md
```

## Setup

### 1. Create GitHub App

Go to https://github.com/settings/apps and create a new GitHub App:

- **App name:** your-app-name
- **Homepage URL:** http://localhost:3000
- **Callback URL:** http://localhost:3000/callback
- **Request user authorization during installation:** ✓
- **Webhook Active:** uncheck

**Permissions:**
- Repository: Contents (Read & Write)
- Repository: Issues (Read & Write)
- Repository: Workflows (Read & Write)
- Account: Email addresses (Read-only)

After creation, generate a Client Secret and note the Client ID.

### 2. Set Environment Variables

```bash
export GITHUB_CLIENT_ID="your_client_id"
export GITHUB_CLIENT_SECRET="your_client_secret"
export GITHUB_APP_SLUG="your-app-name"
```

### 3. Run Services

Open 3 terminal windows:

**Terminal 1 - Auth Service:**
```bash
cd auth-service
go run main.go
```

**Terminal 2 - Tenant A:**
```bash
cd tenant-service
TENANT_NAME="Acme Corp" PORT=3001 go run main.go
```

**Terminal 3 - Tenant B:**
```bash
cd tenant-service
TENANT_NAME="Globex Inc" PORT=3002 go run main.go
```

## Test

1. Open http://localhost:3001 → Acme Corp login page
2. Click "Sign in with GitHub"
3. Authorize and install GitHub App (select repositories)
4. You will see the dashboard with your repos

5. Open http://localhost:3002 → Globex Inc login page
6. Click "Sign in with GitHub"
7. Same flow, ends up on Globex Inc dashboard

8. Logout and login again → Goes directly to dashboard (no installation prompt)

## How It Works

### First Login
1. User clicks "Sign in with GitHub" on Tenant
2. Tenant redirects to Auth Service `/login?tenant=URL`
3. Auth Service stores tenant URL in state, redirects to GitHub OAuth
4. User authorizes on GitHub
5. GitHub calls Auth Service `/callback` with code
6. Auth Service exchanges code for token, gets user info
7. Auth Service creates temp token, redirects to Tenant `/auth/complete`
8. Tenant exchanges temp token with Auth Service `/exchange`
9. User has no InstallationID → Redirect to GitHub App installation
10. User selects repositories and installs
11. GitHub calls Auth Service `/callback` with installation_id
12. Auth Service redirects to Tenant with installation_id
13. Tenant saves user with InstallationID, redirects to Dashboard

### Second Login
1. User clicks "Sign in with GitHub" on Tenant
2. Same OAuth flow (steps 2-8)
3. Tenant checks: User exists in DB with InstallationID
4. Preserve existing InstallationID
5. Redirect directly to Dashboard (skip installation)

## Environment Variables

### Auth Service (:3000)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| GITHUB_CLIENT_ID | Yes | - | GitHub App Client ID |
| GITHUB_CLIENT_SECRET | Yes | - | GitHub App Client Secret |
| GITHUB_APP_SLUG | Yes | - | GitHub App slug from URL |
| AUTH_SERVICE_URL | No | http://localhost:3000 | Auth service public URL |
| PORT | No | 3000 | Server port |

### Tenant Service

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| TENANT_NAME | No | Tenant | Display name for tenant |
| PORT | No | 3001 | Server port |
| TENANT_URL | No | http://localhost:{PORT} | Tenant public URL |
| AUTH_SERVICE_URL | No | http://localhost:3000 | Auth service URL |

## API Endpoints

### Auth Service

| Endpoint | Description |
|----------|-------------|
| GET /login?tenant=URL | Start OAuth flow, stores tenant URL in state |
| GET /callback | GitHub OAuth/Installation callback |
| GET /install?tenant=URL | Start GitHub App installation |
| GET /exchange?token=XXX | Exchange temp token for user data |

### Tenant Service

| Endpoint | Description |
|----------|-------------|
| GET / | Login page |
| GET /auth/github | Redirects to Auth Service /login |
| GET /auth/complete?token=XXX | Receives callback from Auth Service |
| GET /install | Redirects to Auth Service /install |
| GET /dashboard | Shows user info and repositories |
| GET /logout | Clears session |