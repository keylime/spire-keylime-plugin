package keylime

import (
	"crypto/rand"
	"encoding/base32"
)

const PluginName = "keylime"
const KeylimeAPIVersion = "v2.2"

// We use a 32 bytes nonce to provide enough cryptographical randomness and to be
// consistent with other nonces sizes around the project.
const keylimeNonceSize = 32

type AttestationRequest struct {
	AgentID []byte
	HashAlg []byte
}

type ChallengeRequest struct {
	Nonce []byte
}

type ChallengeResponse struct {
	TPMQuote []byte
}

func NewNonce() (string, error) {
	randomBytes, err := GetRandomBytes(keylimeNonceSize)
	if err != nil {
		return "", err
	}
	nonce := base32.StdEncoding.EncodeToString(randomBytes)[:keylimeNonceSize]

	return nonce, nil
}

func GetRandomBytes(size int) ([]byte, error) {
	rndBytes := make([]byte, size)
	_, err := rand.Read(rndBytes)
	if err != nil {
		return nil, err
	}
	return rndBytes, nil
}
