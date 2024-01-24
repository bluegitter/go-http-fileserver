package util

import "crypto/rand"

func GenerateSecretKey() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		panic("generate SecretKey error.")
	}

	for i, v := range b {
		b[i] = charset[v%byte(len(charset))]
	}

	return "sk-" + string(b)
}
