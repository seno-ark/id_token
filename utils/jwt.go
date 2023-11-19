package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type JwtPayload struct {
	Issuer   string                 `json:"iss"`
	Audience string                 `json:"aud"`
	Expires  int64                  `json:"exp"`
	IssuedAt int64                  `json:"iat"`
	Subject  string                 `json:"sub,omitempty"`
	Claims   map[string]interface{} `json:"-"`
}

type jwt struct {
	header    string
	payload   string
	signature string
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

func ParseJWT(idtoken string) (*jwt, error) {
	parts := strings.Split(idtoken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token must have three parts; found %d", len(parts))
	}

	return &jwt{
		header:    parts[0],
		payload:   parts[1],
		signature: parts[2],
	}, nil
}

func (j *jwt) ParseHeader() (header jwtHeader, err error) {
	decodedHeader, err := base64.RawURLEncoding.DecodeString(j.header)
	if err != nil {
		return
	}

	if err := json.Unmarshal(decodedHeader, &header); err != nil {
		return header, fmt.Errorf("unable to unmarshal JWT header: %v", err)
	}

	return
}

func (j *jwt) ParsePayload() (payload JwtPayload, err error) {
	decodedPayload, err := base64.RawURLEncoding.DecodeString(j.payload)
	if err != nil {
		return
	}

	if err := json.Unmarshal(decodedPayload, &payload); err != nil {
		return payload, fmt.Errorf("unable to unmarshal JWT payload: %v", err)
	}
	if err := json.Unmarshal(decodedPayload, &payload.Claims); err != nil {
		return payload, fmt.Errorf("unable to unmarshal JWT payload claims: %v", err)
	}

	return
}

func (j *jwt) DecodeSignature() ([]byte, error) {
	s, err := base64.RawURLEncoding.DecodeString(j.signature)
	if err != nil {
		return nil, fmt.Errorf("unable to decode JWT signature: %v", err)
	}
	return s, nil
}

func (j *jwt) HashContent() []byte {
	signedContent := j.header + "." + j.payload
	hashed := sha256.Sum256([]byte(signedContent))
	return hashed[:]
}
