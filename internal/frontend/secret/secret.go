// Package secret is a frontend handler that provides the /secret endpoint.
package secret

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tinkerbell/hegel/internal/http/request"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
)

type EncryptionStrategy string

type Data struct {
	Secret     string
	Encryption Encryption
}

type Encryption struct {
	// Algorithm is the type of encryption algorithm to use. This should match the defined Key.
	Algorithm string
	// Key is the key to use for encryption.
	Key string
	// Strategy is the type, or lack there of, of encryption to use.
	Strategy EncryptionStrategy
}

type KeyRef struct {
	Name      string
	Namespace string
}

type Response struct {
	// Data will always be base64 encoded. If a key is provided by the Hardware object, it will be encrypted with the public key.
	Data       string             `json:"data"`
	Encryption EncryptionResponse `json:"encryption"`
	//SymmetricKey string         `json:"symmetric_key"`
	//IV           string         `json:"iv"`
	//Mode         EncryptionMode `json:"mode"`
}

type EncryptionResponse struct {
	// SymmeticKey will always be base64 encoded in addition to being encrypted. If a key is provided by the Hardware object, it will be encrypted with the public key.
	SymmetricKey string             `json:"symmetric_key"`
	IV           string             `json:"iv"`
	Mode         EncryptionStrategy `json:"mode"`
}

const (
	// ModePublicKey is the mode for public key encryption.
	ModePublicKey EncryptionStrategy = "public-key"
	// ModeShareKey is the mode for shared key encryption.
	ModeSharedKey EncryptionStrategy = "shared-key"
	// ModeBase64Only is the mode for only using base64 encoding.
	ModeBase64Only EncryptionStrategy = "base64-only"
)

type Client interface {
	GetSecret(ctx context.Context, ip string) (Data, error)
}

func Configure(router gin.IRouter, client Client) {
	router.GET("/secret", func(ctx *gin.Context) {
		ip, err := request.RemoteAddrIP(ctx.Request)
		if err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, errors.New("invalid remote address"))
		}
		d, err := client.GetSecret(ctx, ip)
		if err != nil {
			code := http.StatusInternalServerError
			if kerrors.IsNotFound(err) {
				code = http.StatusNotFound
			}
			err = ctx.AbortWithError(code, err)
			return
		}
		// Generate a symmetric key and encrypt the secret.
		// Encrypt the symmetric key with the public key.
		// Should i encrypt the data with the public key too?

		if d.Secret == "" {
			_ = ctx.AbortWithError(http.StatusNotFound, errors.New("no secret defined"))
			return
		}

		switch d.Encryption.Strategy {
		case ModePublicKey:
			if d.Encryption.Key == "" {
				_ = ctx.AbortWithError(http.StatusBadRequest, errors.New("no encryption key (public key) defined"))
				return
			}
			r, err := publicKeyEncryption(d.Secret, d.Encryption)
			if err != nil {
				_ = ctx.AbortWithError(http.StatusInternalServerError, err)
				return
			}
			r.Encryption.Mode = ModePublicKey
			ctx.JSON(http.StatusOK, r)

			return
		case ModeSharedKey:
			if d.Encryption.Key == "" {
				_ = ctx.AbortWithError(http.StatusBadRequest, errors.New("no encryption key (shared key) defined"))
				return
			}
			key, err := hex.DecodeString(d.Encryption.Key)
			if err != nil {
				_ = ctx.AbortWithError(http.StatusInternalServerError, err)
				return
			}
			iv, dataEnc, err := symmetricEncrypt(key, d.Secret)
			if err != nil {
				_ = ctx.AbortWithError(http.StatusInternalServerError, err)
				return
			}
			r := Response{
				Data: dataEnc,
				Encryption: EncryptionResponse{
					IV: iv,
				},
			}
			r.Encryption.Mode = ModeSharedKey
			ctx.JSON(http.StatusOK, r)

			return
		case ModeBase64Only:
			r := Response{
				Data: base64.StdEncoding.EncodeToString([]byte(d.Secret)),
			}
			r.Encryption.Mode = ModeBase64Only
			ctx.JSON(http.StatusOK, r)

			return
		}

		ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("invalid encryption mode: %s", d.Encryption.Strategy))
	})
}

func publicKeyEncryption(secretData string, e Encryption) (Response, error) {
	key := make([]byte, 32) //generate a random 32 byte key for AES-256
	if _, err := rand.Read(key); err != nil {
		return Response{}, err
	}
	iv, enc, err := symmetricEncrypt(key, secretData)
	if err != nil {
		return Response{}, err
	}
	r := Response{}
	r.Data = enc
	r.Encryption.IV = iv

	// Encrypt the key with the public key

	// Load X.509/SPKI key
	spkiBlock, _ := pem.Decode([]byte(e.Key))
	if spkiBlock == nil {
		return Response{}, errors.New("failed to decode public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
	if err != nil {
		return Response{}, errors.New("failed to parse public key")
	}
	// Use d.Signing.algorithm to determine the type of key
	// then use a switch statement to cast the key to the correct type
	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return Response{}, errors.New("failed to parse public key")
	}

	ek, err := encryptWithPubKey(key, pub)
	if err != nil {
		return Response{}, errors.New("failed to encrypt key")
	}
	r.Encryption.SymmetricKey = base64.StdEncoding.EncodeToString(ek)

	return r, nil
}

// encryptWithPubKey data using rsa public key
// decrypt with tpm: echo "<base64 encoded data>" | base64 -d > secret.enc; tpm2_rsadecrypt -c 0x81008000 -o plain.text secret.enc
func encryptWithPubKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	msg = []byte(hex.EncodeToString(msg))
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	// OAEP doesn't work with my TPM
	// ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// key must be 32 bytes
func symmetricEncrypt(key []byte, data string) (hexEncodedIV, base64EncodedData string, err error) {
	plaintext := pkcs7Padding([]byte(data))

	// 32-byte key for AES-256
	if len(key) != 32 {
		return "", "", fmt.Errorf("key must be 32 bytes")
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Create a new GCM
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return hex.EncodeToString(iv), base64.StdEncoding.EncodeToString(ciphertext), nil
}

func pkcs7Padding(ciphertext []byte) []byte {
	padding := aes.BlockSize - len(ciphertext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// decryptMessage decrypts a message using the provided key.
// openssl enc -aes-256-cbc -d -K <hex formatted asymmetric key> -iv <hex formatted IV> -base64 -in data.enc | tail -c +17
// echo "" | base64 -d > data.enc; openssl enc -aes-256-cbc -d -K <hex formatted asymmetric key> -iv <hex formatted IV> -in data.enc | tail -c +17
// not used at the moment. also, doesnt do the tail -c +17
func decryptMessage(key []byte, message string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	fmt.Printf("iv: %s\n", iv)
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}
