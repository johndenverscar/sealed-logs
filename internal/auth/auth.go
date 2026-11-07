// Package auth mints and checks the prototype's tokens. A shared HMAC secret stands in
// for real identity: project API tokens, Kubernetes workload tokens and SSO.
package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"sealedlogs/internal/config"
)

const (
	RoleMember   = "member"   // a customer user in the project
	RoleStaff    = "staff"    // an operator employee
	RoleProducer = "producer" // a sidecar or SDK writing logs
)

type Claims struct {
	Project string `json:"project"`
	Role    string `json:"role"`
	jwt.RegisteredClaims
}

func secret() []byte {
	return []byte(config.Env("SEALED_TOKEN_SECRET", "dev-only-not-a-secret"))
}

func Mint(sub, project, role string, ttl time.Duration) string {
	c := Claims{
		Project: project,
		Role:    role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
		},
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(secret())
	if err != nil {
		panic(err)
	}
	return s
}

func Parse(tok string) (*Claims, error) {
	c := &Claims{}
	_, err := jwt.ParseWithClaims(tok, c, func(*jwt.Token) (any, error) { return secret(), nil },
		jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	return c, nil
}

func FromRequest(r *http.Request) (*Claims, string, error) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		return nil, "", errors.New("missing bearer token")
	}
	c, err := Parse(tok)
	return c, tok, err
}

// Demo identities shared by the CLI and the TUI.
func DemoToken(as string) string {
	switch as {
	case "staff":
		return Mint("s_bob@example.com", "", RoleStaff, time.Hour)
	case "other":
		return Mint("u_mallory", "p_other", RoleMember, time.Hour)
	case "producer":
		return Mint("w_sidecar", config.DemoProject, RoleProducer, time.Hour)
	default:
		return Mint("u_alice", config.DemoProject, RoleMember, time.Hour)
	}
}
