package cryptography

import (
	"crypto/rand"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/scrypt"
	"io"
)

func GenerateKey(keyLen int) ([]byte, error) {
	password := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, password); err != nil {
		logrus.Error("[GenerateKey] ReadFull error, err=", err)
		return nil, err
	}
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		logrus.Error("[GenerateKey] ReadFull error, err=", err)
		return nil, err
	}
	hashKey, err := scrypt.Key(password, salt, 32768, 8, 1, keyLen)
	if err != nil {
		logrus.Error("[GenerateKey] error, err=", err)
		return nil, err
	}
	return hashKey, nil
}

func GenerateKeyByString(password []byte, keyLen int) ([]byte, error) {
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		logrus.Error("[GenerateKeyByString] error, err=", err)
		return nil, err
	}
	hashKey, err := scrypt.Key(password, salt, 32768, 8, 1, keyLen)
	if err != nil {
		logrus.Error("[GenerateKeyByString] error, err=", err)
		return nil, err
	}
	return hashKey, nil
}
