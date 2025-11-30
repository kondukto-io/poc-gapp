package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// ============================================
// Configuration
// ============================================

/*
export GITHUB_CLIENT_ID="Iv23li9GDF0UExV8VgFF"

export GITHUB_CLIENT_SECRET="9124869d94b50315da43f5b2dfebf630bad5d1ce"

GITHUB_CLIENT_SECRET="9124869d94b50315da43f5b2dfebf630bad5d1ce"
*/
var (
	GitHubClientID     = os.Getenv("GITHUB_CLIENT_ID")
	GitHubClientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
	GitHubAppSlug      = os.Getenv("GITHUB_APP_SLUG")
	AuthServiceURL     = getEnv("AUTH_SERVICE_URL", "http://localhost:3000")
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ============================================
// Storage for OAuth state
// ============================================

type OAuthState struct {
	TenantURL string // Where to redirect after auth
	ExpiresAt time.Time
}

type StateStore struct {
	mu     sync.RWMutex
	states map[string]*OAuthState
}

func NewStateStore() *StateStore {
	return &StateStore{states: make(map[string]*OAuthState)}
}

var stateStore = NewStateStore()

func generateToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *StateStore) Create(tenantURL string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := generateToken(16)
	s.states[state] = &OAuthState{
		TenantURL: tenantURL,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	return state
}

func (s *StateStore) Get(state string) *OAuthState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[state]
	if !ok || time.Now().After(st.ExpiresAt) {
		return nil
	}
	delete(s.states, state)
	return st
}

// ============================================
// Temporary token store (for tenant exchange)
// ============================================

type AuthResult struct {
	AccessToken    string
	GitHubUserID   int64
	GitHubLogin    string
	GitHubName     string
	GitHubAvatar   string
	InstallationID int64
	ExpiresAt      time.Time
}

type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*AuthResult
}

func NewTokenStore() *TokenStore {
	return &TokenStore{tokens: make(map[string]*AuthResult)}
}

var tokenStore = NewTokenStore()

func (t *TokenStore) Create(result *AuthResult) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	token := generateToken(32)
	result.ExpiresAt = time.Now().Add(5 * time.Minute)
	t.tokens[token] = result
	return token
}

func (t *TokenStore) Get(token string) *AuthResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	result, ok := t.tokens[token]
	if !ok || time.Now().After(result.ExpiresAt) {
		return nil
	}
	delete(t.tokens, token)
	return result
}

// ============================================
// GitHub API
// ============================================

type GitHubTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

type GitHubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

func exchangeCodeForToken(code string) (*GitHubTokenResponse, error) {
	url := fmt.Sprintf(
		"https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s",
		GitHubClientID, GitHubClientSecret, code,
	)
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp GitHubTokenResponse
	json.NewDecoder(resp.Body).Decode(&tokenResp)
	return &tokenResp, nil
}

func getGitHubUser(accessToken string) (*GitHubUser, error) {
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var user GitHubUser
	json.Unmarshal(body, &user)
	return &user, nil
}

// ============================================
// HTTP Handlers
// ============================================

// GET /login?tenant=http://localhost:3001
func loginHandler(w http.ResponseWriter, r *http.Request) {
	tenantURL := r.URL.Query().Get("tenant")
	if tenantURL == "" {
		http.Error(w, "Missing tenant parameter", http.StatusBadRequest)
		return
	}

	// Validate tenant URL
	if _, err := url.Parse(tenantURL); err != nil {
		http.Error(w, "Invalid tenant URL", http.StatusBadRequest)
		return
	}

	state := stateStore.Create(tenantURL)

	githubURL := fmt.Sprintf(
		"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s/callback&scope=user:email&state=%s",
		GitHubClientID, AuthServiceURL, state,
	)

	log.Printf("🔐 Login request from tenant: %s", tenantURL)
	http.Redirect(w, r, githubURL, http.StatusFound)
}

// GET /callback (GitHub OAuth callback)
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	installationID := r.URL.Query().Get("installation_id")

	// Get stored state
	oauthState := stateStore.Get(state)
	if oauthState == nil {
		http.Error(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	tokenResp, err := exchangeCodeForToken(code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Get user info
	ghUser, err := getGitHubUser(tokenResp.AccessToken)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Store auth result temporarily
	result := &AuthResult{
		AccessToken:  tokenResp.AccessToken,
		GitHubUserID: ghUser.ID,
		GitHubLogin:  ghUser.Login,
		GitHubName:   ghUser.Name,
		GitHubAvatar: ghUser.AvatarURL,
	}

	// Check if this is an installation callback
	if installationID != "" {
		fmt.Sscanf(installationID, "%d", &result.InstallationID)
		log.Printf("✅ GitHub App installed! Installation ID: %s", installationID)
	}

	// Create temporary token for tenant
	tempToken := tokenStore.Create(result)

	// Redirect to tenant with token
	redirectURL := fmt.Sprintf("%s/auth/complete?token=%s", oauthState.TenantURL, tempToken)
	log.Printf("✅ Auth complete for %s, redirecting to %s", ghUser.Login, oauthState.TenantURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// GET /install?tenant=http://localhost:3001&state=xxx
func installHandler(w http.ResponseWriter, r *http.Request) {
	tenantURL := r.URL.Query().Get("tenant")
	if tenantURL == "" {
		http.Error(w, "Missing tenant parameter", http.StatusBadRequest)
		return
	}

	state := stateStore.Create(tenantURL)

	// Redirect to GitHub App installation with state
	installURL := fmt.Sprintf(
		"https://github.com/apps/%s/installations/new?state=%s",
		GitHubAppSlug, state,
	)

	log.Printf("📦 Install request from tenant: %s", tenantURL)
	http.Redirect(w, r, installURL, http.StatusFound)
}

// GET /exchange?token=xxx (tenant calls this to get user data)
func exchangeHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	result := tokenStore.Get(token)
	if result == nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// GET / (health check / info)
func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"service":    "auth-service",
		"status":     "running",
		"github_app": GitHubAppSlug,
	})
}

// ============================================
// Main
// ============================================

func main() {
	if GitHubClientID == "" || GitHubClientSecret == "" || GitHubAppSlug == "" {
		log.Println("⚠️  Required environment variables:")
		log.Println("   export GITHUB_CLIENT_ID=xxx")
		log.Println("   export GITHUB_CLIENT_SECRET=xxx")
		log.Println("   export GITHUB_APP_SLUG=xxx")
		log.Println("")
	}

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/install", installHandler)
	http.HandleFunc("/exchange", exchangeHandler)

	port := getEnv("PORT", "3000")
	log.Printf("🔐 Auth Service running at http://localhost:%s", port)
	log.Printf("📋 GitHub Callback URL: %s/callback", AuthServiceURL)
	log.Printf("")
	log.Printf("Endpoints:")
	log.Printf("  GET /login?tenant=URL    - Start OAuth flow")
	log.Printf("  GET /install?tenant=URL  - Start App installation")
	log.Printf("  GET /exchange?token=XXX  - Exchange temp token for user data")
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
