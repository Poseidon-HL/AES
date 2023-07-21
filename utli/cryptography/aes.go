package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"github.com/sirupsen/logrus"
	"io"
)

// EncryptAES 采用AES算法进行数据加密，明文长度至少需要大于等于BlockSize，key长度需满足AES算法要求
func EncryptAES(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key) // NewCipher creates and returns a new cipher.Block.
	if err != nil {
		logrus.Error("[EncryptAES] error, err=", err)
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)
	return ciphertext, nil
}

func DecryptAES(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		logrus.Error("[DecryptAES] error, err=", err)
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	block.Decrypt(plaintext, ciphertext)
	return plaintext, nil
}

// EncryptAESByCBC AES CBC模式加密
func EncryptAESByCBC(key []byte, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		logrus.Error("[EncryptAESByCBC] error, err=", err)
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	// 初始化向量直接放置于密文中，只需要保证初始化向量的唯一性，不需要保证其安全性
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		logrus.Error("[EncryptAESByCBC] ReadFull error, err=", err)
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// DecryptAESByCBC AES CBC模式解密，ciphertext中包含iv
func DecryptAESByCBC(key []byte, ciphertext []byte) ([]byte, error) {
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		logrus.Error("[DecryptAESByCBC] error, err=", err)
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}
