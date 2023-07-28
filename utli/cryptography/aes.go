package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"github.com/sirupsen/logrus"
	"github.com/zenazn/pkcs7pad"
	"io"
)

// EncryptAES 只加密了16字节，采用AES算法进行数据加密，明文长度至少需要大于等于BlockSize，key长度需满足AES算法要求
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

// EncryptAESByECB 自动不全后完成加密
func EncryptAESByECB(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		logrus.Error("[EncryptAESByECB] error, err=", err)
		return nil, err
	}
	plaintext = pkcs7pad.Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext)/aes.BlockSize; i++ {
		block.Encrypt(ciphertext[i*aes.BlockSize:(i+1)*aes.BlockSize], plaintext[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
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

func DecryptAESByECB(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		logrus.Error("[DecryptAESByECB] error, err=", err)
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext)/aes.BlockSize; i++ {
		block.Decrypt(plaintext[i*aes.BlockSize:(i+1)*aes.BlockSize], ciphertext[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	plaintext, err = pkcs7pad.Unpad(plaintext)
	if err != nil {
		logrus.Error("[DecryptAESByECB] unPad error, err=", err)
		return nil, err
	}
	return plaintext, nil
}

// EncryptAESByCBC AES CBC模式加密
func EncryptAESByCBC(key []byte, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		logrus.Error("[EncryptAESByCBC] NewCipher error, err=", err)
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

func EncryptAESByCFB(key []byte, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		logrus.Error("[EncryptAESByCFB] NewCipher error, err=", err)
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		logrus.Error("[EncryptAESByCFB] ReadFull error, err=", err)
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
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

func DecryptAESByCFB(key []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		logrus.Error("[DecryptAESByCFB] error, err=", err)
		return nil, err
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}
