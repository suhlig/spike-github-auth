# Spike on GitHub Authentication

Simplest web app that requires a user to log in with GitHub. Access is only allowed if the user is member of a specific team.

# Configuration

* Create a [new OAuth2 application in GitHub](https://github.com/settings/developers) and set the `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`.
* Create a long random string for `SESSION_SECRET_KEY`; e.g. via `openssl rand -base64 64`
* Set the config as env vars:

```command
GITHUB_CLIENT_ID=…
GITHUB_CLIENT_SECRET=…
REDIRECT_URI=http://localhost:8080/callback
GITHUB_ORG=my-org
GITHUB_TEAM_SLUG=my-team
SESSION_SECRET_KEY=…
```

# Iterate

```command
$ while true; do
  fd | entr -r -d go run .
  sleep 0.1
done
```
