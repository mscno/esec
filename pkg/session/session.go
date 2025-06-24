package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecretKey []byte
var sessionDuration time.Duration

// Claims defines the structure of our JWT claims.
type Claims struct {
	GithubUserID string `json:"github_user_id"`
	GithubLogin  string `json:"github_login"`
	jwt.RegisteredClaims
}

// ErrSessionTokenInvalid is returned when a session token is invalid or expired.
var ErrSessionTokenInvalid = errors.New("session token is invalid or expired")

// Configure initializes the session package with necessary settings.
func Configure(secret string, durationHours int) error {
	if secret == "" {
		return errors.New("JWT secret key cannot be empty")
	}
	jwtSecretKey = []byte(secret)
	if durationHours <= 0 {
		durationHours = 24 // Default to 24 hours
	}
	sessionDuration = time.Duration(durationHours) * time.Hour
	return nil
}

// GenerateToken creates a new session token for a user.
func GenerateToken(githubUserID, githubLogin string) (string, int64, error) {
	if len(jwtSecretKey) == 0 {
		return "", 0, errors.New("JWT secret key not configured")
	}
	expirationTime := time.Now().Add(sessionDuration)
	claims := &Claims{
		GithubUserID: githubUserID,
		GithubLogin:  githubLogin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "esec-server",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", 0, fmt.Errorf("failed to sign session token: %w", err)
	}
	return tokenString, expirationTime.Unix(), nil
}

// ValidateToken checks the validity of a session token string.
func ValidateToken(tokenStr string) (*Claims, error) {
	if len(jwtSecretKey) == 0 {
		return nil, errors.New("JWT secret key not configured")
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrSessionTokenInvalid
		}
		return nil, fmt.Errorf("failed to parse session token: %w", err)
	}

	if !token.Valid {
		return nil, ErrSessionTokenInvalid
	}
	return claims, nil
}
