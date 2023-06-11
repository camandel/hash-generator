package main

import (
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var secretKey = []byte(os.Getenv("SECRET_KEY"))

type JWTClaim struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do stuff here
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}

func GenerateJWT(email string) (tokenString string, err error) {
	expirationTime := time.Now().Add(1 * time.Hour)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	claims := &JWTClaim{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(secretKey)
	return tokenString, err
}

func ValidateToken(signedToken string) (c *JWTClaim, err error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		},
	)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*JWTClaim)
	if !ok {
		err = errors.New("couldn't parse claims")
		return nil, err
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		err = errors.New("token expired")
		return nil, err
	}
	return claims, nil
}

func GeneratePasswordHash(password string) string {
	pepperedPassword := password + os.Getenv("SECRET_KEY")
	hash, _ := bcrypt.GenerateFromPassword([]byte(pepperedPassword), bcrypt.DefaultCost)
	return string(hash)
}

func CheckPasswordHash(password, hash string) bool {
	pepperedPassword := password + os.Getenv("SECRET_KEY")
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pepperedPassword))
	return err == nil
}

func checkEnvVars() error {
	if os.Getenv("USER_PWD") == "" || os.Getenv("SECRET_KEY") == "" || os.Getenv("FLAG") == "" {
		return errors.New("environment variables missing: USER_PWD, SECRET_KEY or FLAG")
	}
	if len(os.Getenv("SECRET_KEY")) > 32 {
		return errors.New("SECRET_KEY max lenght is 32 characters")
	}
	return nil
}
