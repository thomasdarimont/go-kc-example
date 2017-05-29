/*
This is an example application to demonstrate querying the user info endpoint.
*/
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"fmt"

	oidc "github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/thomasdarimont/go-kc-example/session"
	_ "github.com/thomasdarimont/go-kc-example/session_memory"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	clientID     = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
)

const oauth_state = "oauth_state"

type GoUserInfo struct {
	userID      string
	email       string
	username    string
	displayName string
}

var globalSessions *session.Manager

// Then, initialize the session manager
func init() {
	globalSessions, _ = session.NewManager("memory", "gosessionid", 3600)
	go globalSessions.GC()
}

func main() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "http://localhost:8081/auth/realms/godemo")

	if err != nil {
		log.Fatal(err)
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://127.0.0.1:5556/auth/keycloak/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(oidcConfig)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		sess := globalSessions.SessionStart(w, r)

		oauthState := uuid.New().String()
		sess.Set(oauth_state, oauthState)

		userInfo := sess.Get("userinfo")
		if userInfo == nil {
			http.Redirect(w, r, config.AuthCodeURL(oauthState), http.StatusFound)
			return
		}

		http.Redirect(w, r, "/app", http.StatusFound)
	})

	http.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {

		w.WriteHeader(http.StatusOK)
		sess := globalSessions.SessionStart(w, r)
		userInfo := sess.Get("userinfo").(*GoUserInfo)
		fmt.Fprintf(w, "Welcome: %s\n", userInfo)
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {

		sess := globalSessions.SessionStart(w, r)

		oauthState := uuid.New().String()
		sess.Set(oauth_state, oauthState)

		userInfo := sess.Get("userinfo")
		if userInfo == nil {
			http.Redirect(w, r, config.AuthCodeURL(oauthState), http.StatusFound)
			return
		}

		fmt.Printf("logout %s\n", userInfo.(*GoUserInfo).userID)

		rawIDtoken := sess.Get("rawIDToken").(string)

		redirect, err := provider.Logout(ctx, nil, rawIDtoken, "http://127.0.0.1:5556/", oauthState) //TODO handle state token on logout
		if err != nil {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		globalSessions.SessionDestroy(w, r)
		http.Redirect(w, r, redirect, http.StatusFound)
	})

	http.HandleFunc("/auth/keycloak/callback", func(w http.ResponseWriter, r *http.Request) {

		sess := globalSessions.SessionStart(w, r)

		oauthState := sess.Get(oauth_state)
		if oauthState == nil {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		if r.URL.Query().Get("state") != oauthState.(string) {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		_, err = verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		sess.Set("userinfo", &GoUserInfo{
			userID:      userInfo.Subject,
			username:    userInfo.PreferredUsername,
			displayName: userInfo.Name,
			email:       userInfo.Email,
		})

		sess.Set("rawIDToken", rawIDToken)

		resp := struct {
			OAuth2Token *oauth2.Token
			UserInfo    *oidc.UserInfo
		}{oauth2Token, userInfo}
		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	log.Printf("listening on http://%s/", "127.0.0.1:5556")
	log.Fatal(http.ListenAndServe("127.0.0.1:5556", nil))
}
