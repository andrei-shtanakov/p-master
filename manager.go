package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

type PasswordEntry struct {
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type GithubSecretsManager struct {
	token         string
	owner         string
	repo          string
	keyFile       string
	encryptionKey []byte
}

func NewGithubSecretsManager(token, owner, repo, keyFile string) (*GithubSecretsManager, error) {
	key := make([]byte, 32)
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		// Generate new key if it doesn't exist
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("failed to generate key: %v", err)
		}
		if err := os.WriteFile(keyFile, key, 0600); err != nil {
			return nil, fmt.Errorf("failed to save key: %v", err)
		}
	} else {
		// Read existing key
		var err error
		key, err = os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key: %v", err)
		}
	}

	return &GithubSecretsManager{
		token:         token,
		owner:         owner,
		repo:          repo,
		keyFile:       keyFile,
		encryptionKey: key,
	}, nil
}

func (g *GithubSecretsManager) encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(g.encryptionKey)
	if err != nil {
		return "", err
	}

	// Create a new GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// Encrypt and combine nonce with encrypted data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (g *GithubSecretsManager) decrypt(encryptedData string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(g.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (g *GithubSecretsManager) SavePassword(entry PasswordEntry) error {
	// Create a secret name from service and username
	secretName := fmt.Sprintf("PWD_%s_%s",
		strings.ToUpper(strings.ReplaceAll(entry.Service, "-", "_")),
		strings.ToUpper(strings.ReplaceAll(entry.Username, "-", "_")))

	// Encrypt the password
	encryptedPassword, err := g.encrypt([]byte(entry.Password))
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	// Create GitHub API request
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/secrets/%s",
		g.owner, g.repo, secretName)

	payload := map[string]string{
		"encrypted_value": encryptedPassword,
		"key_id":          "github_actions",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to save secret: status %d", resp.StatusCode)
	}

	return nil
}

func main() {
	// Get GitHub token from environment
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("GITHUB_TOKEN environment variable is required")
	}

	// Create a new secrets manager
	manager, err := NewGithubSecretsManager(
		token,
		"andrei-shtanakovyour",
		"p-master",
		"encryption.key",
	)
	if err != nil {
		log.Fatalf("Failed to create secrets manager: %v", err)
	}

	// Example usage
	entry := PasswordEntry{
		Service:  "example-service",
		Username: "user123",
		Password: "securePassword123",
	}

	if err := manager.SavePassword(entry); err != nil {
		log.Fatalf("Failed to save password: %v", err)
	}

	fmt.Println("Password saved successfully!")
}
