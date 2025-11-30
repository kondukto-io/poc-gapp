package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// ============================================
// Configuration
// ============================================

var (
	TenantName     = getEnv("TENANT_NAME", "Tenant")
	Port           = getEnv("PORT", "3001")
	TenantURL      = getEnv("TENANT_URL", "http://localhost:"+Port)
	AuthServiceURL = getEnv("AUTH_SERVICE_URL", "http://localhost:3000")
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ============================================
// Storage
// ============================================

type User struct {
	ID             int64     `json:"id"`
	Login          string    `json:"login"`
	Name           string    `json:"name"`
	AvatarURL      string    `json:"avatar_url"`
	Role           string    `json:"role"`
	AccessToken    string    `json:"access_token"`
	InstallationID int64     `json:"installation_id"`
	CreatedAt      time.Time `json:"created_at"`
}

type Session struct {
	Token     string
	UserID    int64
	ExpiresAt time.Time
}

type Store struct {
	mu       sync.RWMutex
	users    map[int64]*User
	sessions map[string]*Session
}

func NewStore() *Store {
	return &Store{
		users:    make(map[int64]*User),
		sessions: make(map[string]*Session),
	}
}

var store = NewStore()

func generateToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Store) SaveUser(u *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.users[u.ID]; ok {
		u.Role = existing.Role
		u.CreatedAt = existing.CreatedAt
		if u.InstallationID == 0 {
			u.InstallationID = existing.InstallationID
		}
	} else {
		u.Role = "Admin"
		u.CreatedAt = time.Now()
	}
	s.users[u.ID] = u
}

func (s *Store) GetUser(id int64) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[id]
}

func (s *Store) CreateSession(userID int64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := generateToken(32)
	s.sessions[token] = &Session{
		Token:     token,
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	return token
}

func (s *Store) GetSession(token string) (*Session, *User) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[token]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil, nil
	}
	return sess, s.users[sess.UserID]
}

func (s *Store) DeleteSession(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *Store) UserHasInstallation(userID int64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[userID]
	return ok && user.InstallationID > 0
}

// ============================================
// GitHub API (for fetching repos)
// ============================================

type Repository struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
	HTMLURL  string `json:"html_url"`
}

type InstallationReposResponse struct {
	TotalCount   int          `json:"total_count"`
	Repositories []Repository `json:"repositories"`
}

func getInstallationRepositories(accessToken string, installationID int64) ([]Repository, error) {
	url := fmt.Sprintf("https://api.github.com/user/installations/%d/repositories", installationID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var reposResp InstallationReposResponse
	json.Unmarshal(body, &reposResp)
	return reposResp.Repositories, nil
}

// ============================================
// HTTP Handlers
// ============================================

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session"); err == nil {
		if _, user := store.GetSession(cookie.Value); user != nil {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
	}

	data := map[string]string{"TenantName": TenantName}
	tmpl := template.Must(template.New("login").Parse(loginHTML))
	tmpl.Execute(w, data)
}

func githubLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Redirect to auth service
	loginURL := fmt.Sprintf("%s/login?tenant=%s", AuthServiceURL, TenantURL)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// GET /auth/complete?token=xxx (callback from auth service)
func authCompleteHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	// Exchange token with auth service
	exchangeURL := fmt.Sprintf("%s/exchange?token=%s", AuthServiceURL, token)
	resp, err := http.Get(exchangeURL)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var authResult struct {
		AccessToken    string `json:"AccessToken"`
		GitHubUserID   int64  `json:"GitHubUserID"`
		GitHubLogin    string `json:"GitHubLogin"`
		GitHubName     string `json:"GitHubName"`
		GitHubAvatar   string `json:"GitHubAvatar"`
		InstallationID int64  `json:"InstallationID"`
	}
	json.NewDecoder(resp.Body).Decode(&authResult)

	// Check if user already exists (to preserve InstallationID)
	existingUser := store.GetUser(authResult.GitHubUserID)

	// Save user
	user := &User{
		ID:          authResult.GitHubUserID,
		Login:       authResult.GitHubLogin,
		Name:        authResult.GitHubName,
		AvatarURL:   authResult.GitHubAvatar,
		AccessToken: authResult.AccessToken,
	}

	// Preserve existing installation ID if not provided
	if authResult.InstallationID > 0 {
		user.InstallationID = authResult.InstallationID
	} else if existingUser != nil && existingUser.InstallationID > 0 {
		user.InstallationID = existingUser.InstallationID
	}

	store.SaveUser(user)

	// Create session
	sessionToken := store.CreateSession(user.ID)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
	})

	log.Printf("✅ User %s logged in to %s (InstallationID: %d)", user.Login, TenantName, user.InstallationID)

	// Check if needs installation (only if never installed before)
	if user.InstallationID == 0 {
		http.Redirect(w, r, "/install", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func installHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	_, user := store.GetSession(cookie.Value)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if store.UserHasInstallation(user.ID) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// Redirect to auth service for installation
	installURL := fmt.Sprintf("%s/install?tenant=%s", AuthServiceURL, TenantURL)
	http.Redirect(w, r, installURL, http.StatusFound)
}

type DashboardData struct {
	TenantName   string
	User         *User
	Repositories []Repository
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	_, user := store.GetSession(cookie.Value)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	var repos []Repository
	if user.InstallationID > 0 && user.AccessToken != "" {
		repos, _ = getInstallationRepositories(user.AccessToken, user.InstallationID)
	}

	data := DashboardData{
		TenantName:   TenantName,
		User:         user,
		Repositories: repos,
	}

	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))
	tmpl.Execute(w, data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session"); err == nil {
		store.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// ============================================
// HTML Templates
// ============================================

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - {{.TenantName}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: #fff;
            padding: 3rem;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 400px;
            width: 90%;
        }
        .logo { font-size: 3rem; margin-bottom: 1rem; }
        h1 { color: #1a1a2e; margin-bottom: 0.5rem; font-size: 1.8rem; }
        .tenant-badge {
            display: inline-block;
            background: #e0e7ff;
            color: #4338ca;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            margin-bottom: 1.5rem;
        }
        .subtitle { color: #666; margin-bottom: 2rem; }
        .github-btn {
            display: inline-flex;
            align-items: center;
            gap: 12px;
            background: #24292e;
            color: #fff;
            padding: 14px 28px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 1rem;
            transition: all 0.2s;
        }
        .github-btn:hover { background: #000; transform: translateY(-2px); }
        .github-btn svg { width: 24px; height: 24px; fill: #fff; }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="logo">🔐</div>
        <h1>Welcome</h1>
        <div class="tenant-badge">{{.TenantName}}</div>
        <p class="subtitle">Sign in with your GitHub account to continue</p>
        <a href="/auth/github" class="github-btn">
            <svg viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
            Sign in with GitHub
        </a>
    </div>
</body>
</html>`

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - {{.TenantName}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            padding: 2rem;
        }
        .container { max-width: 900px; margin: 0 auto; }
        .header {
            background: #fff;
            padding: 1.5rem 2rem;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 2rem;
        }
        .header-left { display: flex; align-items: center; gap: 1.5rem; }
        .tenant-badge {
            background: #e0e7ff;
            color: #4338ca;
            padding: 6px 14px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9rem;
        }
        .user-info { display: flex; align-items: center; gap: 1rem; }
        .avatar {
            width: 45px;
            height: 45px;
            border-radius: 50%;
            border: 2px solid #10b981;
        }
        .user-details .name { font-weight: 600; color: #1a1a2e; }
        .user-details .login { color: #666; font-size: 0.85rem; }
        .logout-btn {
            background: #ef4444;
            color: #fff;
            padding: 8px 20px;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
        }
        .logout-btn:hover { background: #dc2626; }
        .repos-section {
            background: #fff;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .repos-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid #e5e7eb;
        }
        .repos-header h2 { color: #1a1a2e; font-size: 1.3rem; }
        .repo-count {
            background: #e0e7ff;
            color: #4338ca;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        .repo-list { list-style: none; }
        .repo-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 0.5rem;
            background: #f8fafc;
        }
        .repo-item:hover { background: #f1f5f9; }
        .repo-info { display: flex; align-items: center; gap: 0.75rem; }
        .repo-icon { font-size: 1.3rem; }
        .repo-name { font-weight: 600; color: #1a1a2e; }
        .repo-fullname { color: #666; font-size: 0.85rem; }
        .repo-badge {
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        .repo-badge.private { background: #fef3c7; color: #d97706; }
        .repo-badge.public { background: #d1fae5; color: #059669; }
        .repo-link { color: #6366f1; text-decoration: none; font-size: 0.9rem; }
        .repo-link:hover { text-decoration: underline; }
        .empty-state { text-align: center; padding: 3rem; color: #666; }
        .empty-state .icon { font-size: 3rem; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-left">
                <span class="tenant-badge">{{.TenantName}}</span>
                <div class="user-info">
                    <img src="{{.User.AvatarURL}}" alt="Avatar" class="avatar">
                    <div class="user-details">
                        <div class="name">{{.User.Name}}</div>
                        <div class="login">@{{.User.Login}}</div>
                    </div>
                </div>
            </div>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>

        <div class="repos-section">
            <div class="repos-header">
                <h2>📁 Accessible Repositories</h2>
                <span class="repo-count">{{len .Repositories}} repos</span>
            </div>
            
            {{if .Repositories}}
            <ul class="repo-list">
                {{range .Repositories}}
                <li class="repo-item">
                    <div class="repo-info">
                        <span class="repo-icon">{{if .Private}}🔒{{else}}📂{{end}}</span>
                        <div>
                            <div class="repo-name">{{.Name}}</div>
                            <div class="repo-fullname">{{.FullName}}</div>
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 1rem;">
                        <span class="repo-badge {{if .Private}}private{{else}}public{{end}}">
                            {{if .Private}}Private{{else}}Public{{end}}
                        </span>
                        <a href="{{.HTMLURL}}" target="_blank" class="repo-link">View →</a>
                    </div>
                </li>
                {{end}}
            </ul>
            {{else}}
            <div class="empty-state">
                <div class="icon">📭</div>
                <p>No repositories found. <a href="/install">Install GitHub App</a> to grant access.</p>
            </div>
            {{end}}
        </div>
    </div>
</body>
</html>`

// ============================================
// Main
// ============================================

func main() {
	http.HandleFunc("/", loginPageHandler)
	http.HandleFunc("/auth/github", githubLoginHandler)
	http.HandleFunc("/auth/complete", authCompleteHandler)
	http.HandleFunc("/install", installHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/logout", logoutHandler)

	log.Printf("🏢 %s running at http://localhost:%s", TenantName, Port)
	log.Printf("   Tenant URL: %s", TenantURL)
	log.Printf("   Auth Service: %s", AuthServiceURL)
	log.Fatal(http.ListenAndServe(":"+Port, nil))
}
