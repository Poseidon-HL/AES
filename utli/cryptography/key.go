package cryptography

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/scrypt"
)

func GenerateKeyByString(password []byte, keyLen int) ([]byte, error) {
	// TODO generate salt
	hashKey, err := scrypt.Key(password, []byte("salt"), 32768, 8, 1, keyLen)
	if err != nil {
		logrus.Error("[GenerateKeyByString] error, err=", err)
		return nil, err
	}
	return hashKey, nil
}
