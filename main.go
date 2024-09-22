package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	clientID     string
	clientSecret string
	redirectURI  string
	teamSlug     string
	org          string
)

// User represents the GitHub user data we need
type User struct {
	Login string `json:"login"`
}

// Team represents the GitHub team data
type Team struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
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

	// If user is in the team, proceed to the protected page
	http.Redirect(w, r, "/protected", http.StatusFound)
}

// Protected page handler
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "<h1>Protected Content</h1><p>Welcome to the protected page!</p>")
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

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/protected", protectedHandler)

	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}
