package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

var EncryptDataKey = mustDecodeHex("c77fb810104b9cbda557c7cba44694c1d616858d5ac6c93aa490a53027a9251a")

func mustDecodeHex(h string) []byte {
	b := make([]byte, len(h)/2)
	for i := range b {
		var v byte
		for _, c := range h[i*2 : i*2+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c-'a') + 10
			case c >= 'A' && c <= 'F':
				v |= byte(c-'A') + 10
			}
		}
		b[i] = v
	}
	return b
}

func Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(EncryptDataKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func Decrypt(b64data string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		return b64data, false // not encrypted, return as-is
	}
	block, err := aes.NewCipher(EncryptDataKey)
	if err != nil {
		return b64data, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return b64data, false
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return b64data, false
	}
	plaintext, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return b64data, false 
	}
	return string(plaintext), true
}

func EncryptBytes(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(EncryptDataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func DecryptBytes(data []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, errors.New("data too short")
	}
	block, err := aes.NewCipher(EncryptDataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("data shorter than nonce")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}
