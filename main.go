package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	clientID     string
	clientSecret string
	redirectURI  string
	teamSlug     string
	org          string
	secretKey    string // Key for signing the session cookie
)

// User represents the GitHub user data we need
type User struct {
	Login string `json:"login"`
}

// OAuth2 handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	url := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=read:org", clientID, redirectURI)
	http.Redirect(w, r, url, http.StatusFound)
}

// OAuth2 callback handler
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	// Exchange code for access token
	token, err := getGitHubAccessToken(code)
	if err != nil {
		http.Error(w, "Error fetching access token", http.StatusInternalServerError)
		return
	}

	// Get the authenticated user
	user, err := getGitHubUser(token)
	if err != nil {
		http.Error(w, "Error fetching user", http.StatusInternalServerError)
		return
	}

	// Check if the user belongs to the required team
	if !isUserInTeam(user.Login, token) {
		http.Error(w, "Access denied. Not a member of the required team.", http.StatusForbidden)
		return
	}

	fmt.Fprintf(os.Stderr, "Creating session for %s\n", user.Login)

	// Set user session using a secure signed cookie
	setSignedSession(w, user.Login)

	// Redirect to the protected page after successful login
	http.Redirect(w, r, "/protected", http.StatusFound)
}

// Protected page handler (requires login)
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the user is logged in by verifying the signed session
	user, err := getSignedSession(r)

	if err != nil {
		http.Error(w, "Unauthorized. Please log in first.", http.StatusUnauthorized)
		return
	}

	// If logged in, show the protected content
	fmt.Fprintf(w, "<h1>Protected Content</h1><p>Welcome %s, you have access to the protected page!</p>", user)
}

// SetSignedSession creates a secure, signed session cookie
func setSignedSession(w http.ResponseWriter, username string) {
	expiration := time.Now().Add(24 * time.Hour)
	signedValue := createSignedToken(username, expiration)

	cookie := http.Cookie{
		Name:     "session_user",
		Value:    signedValue,
		Expires:  expiration,
		HttpOnly: true,                 // Prevent JavaScript access
		Secure:   false,                // Should be true in production (HTTPS)
		SameSite: http.SameSiteLaxMode, // Prevent cross-site attacks
		Path:     "/",
	}
	http.SetCookie(w, &cookie)
}

// GetSignedSession retrieves and verifies the signed session cookie
func getSignedSession(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_user")

	if err != nil {
		return "", err
	}

	// Verify the signed token
	username, err := verifySignedToken(cookie.Value)
	if err != nil {
		return "", err
	}

	return username, nil
}

// CreateSignedToken creates an HMAC-SHA256 signed token
func createSignedToken(username string, expiration time.Time) string {
	expiryStr := fmt.Sprintf("%d", expiration.Unix())
	value := username + "|" + expiryStr
	signature := signMessage(value)
	return base64.StdEncoding.EncodeToString([]byte(value + "|" + signature))
}

// VerifySignedToken verifies the token integrity and checks expiration
func verifySignedToken(signedValue string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(signedValue)

	if err != nil {
		return "", fmt.Errorf("Invalid session token")
	}

	parts := strings.Split(string(raw), "|")

	if len(parts) != 3 {
		return "", fmt.Errorf("Invalid session format")
	}

	username := parts[0]
	expiryStr := parts[1]
	signature := parts[2]

	// Verify the signature
	value := username + "|" + expiryStr

	expectedSignature := signMessage(value)

	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return "", fmt.Errorf("Invalid session signature")
	}

	// Check expiration
	expiryUnix, err := parseExpiry(expiryStr)

	if err != nil {
		return "", fmt.Errorf("Invalid session expiration")
	}

	if time.Now().Unix() > expiryUnix {
		return "", fmt.Errorf("Session expired")
	}

	return username, nil
}

// signMessage creates an HMAC-SHA256 signature of the message using the secret key
func signMessage(message string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// parseExpiry converts the expiry timestamp string to Unix time (int64)
func parseExpiry(expiryStr string) (int64, error) {
	return strconv.ParseInt(expiryStr, 10, 64) // Base 10, 64-bit integer
}

// Get GitHub access token
func getGitHubAccessToken(code string) (string, error) {
	url := "https://github.com/login/oauth/access_token"
	req, err := http.NewRequest("POST", url, strings.NewReader(fmt.Sprintf("client_id=%s&client_secret=%s&code=%s", clientID, clientSecret, code)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var res struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}

	return res.AccessToken, nil
}

// Get authenticated GitHub user
func getGitHubUser(token string) (*User, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

// Check if the user belongs to a specific GitHub team
func isUserInTeam(username, token string) bool {
	url := fmt.Sprintf("https://api.github.com/orgs/%s/teams/%s/memberships/%s", org, teamSlug, username)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false
	}

	return resp.StatusCode == http.StatusOK
}

func main() {
	clientID = os.Getenv("GITHUB_CLIENT_ID")
	clientSecret = os.Getenv("GITHUB_CLIENT_SECRET")

	redirectURI = os.Getenv("REDIRECT_URI")
	teamSlug = os.Getenv("GITHUB_TEAM_SLUG")
	org = os.Getenv("GITHUB_ORG")
	secretKey = os.Getenv("SESSION_SECRET_KEY")

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/protected", protectedHandler)

	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
