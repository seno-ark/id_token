package id_token

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"time"

	"github.com/seno-ark/id_token/utils"
)

type Config struct {
	Provider string
	ClientID string
}

type Validator struct {
	auds []string
	jwks []utils.Jwk
}

func NewValidator(conf *Config) (*Validator, error) {
	var openIDUrl string

	switch conf.Provider {
	case GOOGLE:
		openIDUrl = GOOGLE_OPENID_URL
	default:
		return nil, ErrInvalidProvider
	}

	openIdConf, err := utils.GetConfig(context.Background(), openIDUrl)
	if err != nil {
		return nil, err
	}

	if openIdConf.JwksUri == "" {
		return nil, ErrJwksNotFound
	}

	authCert, err := utils.GetCert(context.Background(), openIdConf.JwksUri)
	if err != nil {
		return nil, err
	}

	validator := Validator{
		jwks: authCert.Keys,
	}
	if conf.ClientID != "" {
		validator.auds = append(validator.auds, conf.ClientID)
	}

	return &validator, nil
}

func (v *Validator) Validate(idToken string) (*utils.JwtPayload, error) {
	jwt, err := utils.ParseJWT(idToken)
	if err != nil {
		return nil, err
	}

	header, err := jwt.ParseHeader()
	if err != nil {
		return nil, err
	}

	payload, err := jwt.ParsePayload()
	if err != nil {
		return nil, err
	}

	signature, err := jwt.DecodeSignature()
	if err != nil {
		return nil, err
	}

	if len(v.auds) > 0 {
		if err := v.verifyAudience(payload.Audience); err != nil {
			return nil, err
		}
	}

	if time.Now().UTC().Unix() > payload.Expires {
		return nil, ErrTokenExpired
	}

	switch header.Algorithm {
	case "RS256":
		if err := v.verifyRS256(header.KeyID, jwt.HashContent(), signature); err != nil {
			return nil, err
		}
	default:
		return nil, ErrAlgorithmNotSupported
	}

	return &payload, nil
}

func (v *Validator) verifyAudience(payloadAud string) error {
	var validAud bool
	for _, aud := range v.auds {
		if aud != "" && payloadAud == aud {
			validAud = true
			break
		}
	}
	if !validAud {
		return ErrAudienceNotMatch
	}
	return nil
}

func (v *Validator) verifyRS256(keyID string, content, signature []byte) error {
	var cert *utils.Jwk

	for _, v := range v.jwks {
		if v.Kid == keyID {
			cert = &v
			break
		}
	}

	if cert == nil {
		return ErrKidNotFound
	}

	decodedN, err := base64.RawURLEncoding.DecodeString(cert.N)
	if err != nil {
		return err
	}

	decodedE, err := base64.RawURLEncoding.DecodeString(cert.E)
	if err != nil {
		return err
	}

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(decodedN),
		E: int(new(big.Int).SetBytes(decodedE).Int64()),
	}

	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, content, signature)
}
