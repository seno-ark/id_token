package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type Jwk struct {
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	E   string `json:"e"`
	N   string `json:"n"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksResponse struct {
	Keys []Jwk `json:"keys"`
}

type openIdConfigResponse struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri"`
}

func GetConfig(ctx context.Context, url string) (*openIdConfigResponse, error) {
	client := http.DefaultClient

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to request %s: %d", url, resp.StatusCode)
	}

	confResp := &openIdConfigResponse{}
	if err := json.NewDecoder(resp.Body).Decode(confResp); err != nil {
		return nil, err

	}

	return confResp, nil
}

func GetCert(ctx context.Context, url string) (*jwksResponse, error) {
	client := http.DefaultClient

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to request %s: %d", url, resp.StatusCode)
	}

	certResp := &jwksResponse{}
	if err := json.NewDecoder(resp.Body).Decode(certResp); err != nil {
		return nil, err

	}

	return certResp, nil
}
