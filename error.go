package id_token

import "errors"

var (
	ErrInvalidProvider       = errors.New("invalid provider")
	ErrJwksNotFound          = errors.New("jwks_uri not found")
	ErrTokenExpired          = errors.New("token expired")
	ErrAudienceNotMatch      = errors.New("audience not match")
	ErrAlgorithmNotSupported = errors.New("algorithm not supported")
	ErrKidNotFound           = errors.New("kid not found")
)
