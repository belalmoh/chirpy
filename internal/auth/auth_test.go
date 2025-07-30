package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	password := "password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" {
		t.Fatal("hash is empty")
	}
}

func TestCheckHashPassword(t *testing.T) {
	password := "password"
	hashedPassword, err := HashPassword(password)

	if err != nil {
		t.Fatal(err)
	} else if !CheckHashPassword(password, hashedPassword) {
		t.Fatal("hash is not correct")
	}
}

func TestCreateJWT(t *testing.T) {
	userID := uuid.New()
	token, err := CreateJWT(userID, time.Hour*24)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("token is empty")
	}
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	token, err := CreateJWT(userID, time.Hour*24)
	if err != nil {
		t.Fatal(err)
	}

	parsedUserID, err := ValidateJWT(token)
	if err != nil {
		t.Fatal(err)
	}
	if parsedUserID != userID {
		t.Fatal("userID is not correct")
	}

	wrongToken := "wrongtoken"
	_, err = ValidateJWT(wrongToken)
	if err == nil {
		t.Fatal("token is valid")
	}
}
