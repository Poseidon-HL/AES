package cryptography

import (
	"crypto/aes"
	"errors"
	"github.com/sirupsen/logrus"
	"github.com/zenazn/pkcs7pad"
)

type ECBEncrypt struct {
	blockNum  int  // 分块数
	encrypted bool // 所有块是否加密 true-已经完成加密，block存储密文 false-未完成加密，block存储明文
	key       []byte
	blocks    [][]byte
	// 适用于实验时分块加解密字段
	isExperiment      bool // 是否进行实验 进行实验时只进行部分加解密操作
	encryptedBlockNum int  // 加密块数
	// blockEncrypted [][]bool // 每个块的加密情况
}

func (e *ECBEncrypt) Load(plaintext, key []byte) *ECBEncrypt {
	plaintext = pkcs7pad.Pad(plaintext, aes.BlockSize)
	e.blockNum = len(plaintext) / aes.BlockSize
	e.blocks = make([][]byte, e.blockNum)
	for i := 0; i < e.blockNum; i++ {
		e.blocks[i] = make([]byte, 0)
		e.blocks[i] = append(e.blocks[i], plaintext[i*aes.BlockSize:(i+1)*aes.BlockSize]...)
	}
	e.key = key
	return e
}

func (e *ECBEncrypt) Encrypt() error {
	if e.encrypted {
		return errors.New("[ECBEncrypt.Encrypt] error, already encrypted")
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		logrus.Error("[ECBEncrypt.Encrypt] NewCipher error, err=", err)
		return err
	}
	for i := 0; i < e.blockNum; i++ {
		block.Encrypt(e.blocks[i], e.blocks[i])
	}
	e.encrypted = true
	return nil
}

func (e *ECBEncrypt) Decrypt() error {
	if !e.encrypted {
		return errors.New("[ECBEncrypt.Decrypt] error, not encrypted")
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		logrus.Error("[ECBEncrypt.Decrypt] NewCipher error, err=", err)
		return err
	}
	for i := 0; i < e.blockNum; i++ {
		block.Decrypt(e.blocks[i], e.blocks[i])
	}
	e.encrypted = false
	return nil
}

// GetCipherText 获取密文数据，如果原本未进行加密则先加密
func (e *ECBEncrypt) GetCipherText() []byte {
	if !e.encrypted {
		if err := e.Encrypt(); err != nil {
			return nil
		}
	}
	ciphertext := make([]byte, e.blockNum*aes.BlockSize)
	for i := 0; i < e.blockNum; i++ {
		copy(ciphertext[i*aes.BlockSize:(i+1)*aes.BlockSize], e.blocks[i])
	}
	return ciphertext
}

// GetPlainText 获取明文数据，如果原本已加密则先解密
func (e *ECBEncrypt) GetPlainText() []byte {
	var err error
	if e.encrypted {
		if err = e.Decrypt(); err != nil {
			return nil
		}
	}
	plaintext := make([]byte, 0)
	for i := 0; i < e.blockNum; i++ {
		plaintext = append(plaintext, e.blocks[i]...)
	}
	if plaintext, err = pkcs7pad.Unpad(plaintext); err != nil {
		logrus.Error("[ECBEncrypt.GetPlainText] unPad error, err=", err)
		return nil
	}
	return plaintext
}

// GetBlock 获得某一块内容，不论加密与否
func (e *ECBEncrypt) GetBlock(i int) []byte {
	if i < 0 || i >= e.blockNum {
		return nil
	}
	return e.blocks[i]
}

// GetPlainBlock 获取某一块明文内容，也即如果已经加密则会对该块进行解密
func (e *ECBEncrypt) GetPlainBlock(i int) []byte {
	b := e.GetBlock(i)
	if b == nil || !e.encrypted {
		return b
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		logrus.Error("[ECBEncrypt.GetPlainBlock] NewCipher error, err=", err)
		return nil
	}
	data := make([]byte, aes.BlockSize)
	block.Decrypt(data, b)
	return data
}

func (e *ECBEncrypt) CompareSimilarities(ecb *ECBEncrypt) (float64, error) {
	if e.blockNum != ecb.blockNum || e.encryptedBlockNum != ecb.encryptedBlockNum {
		return 0, errors.New("[CompareSimilarities] can not compare similarities with different parameters")
	}
	sameBytesCnt := float64(0)
	for i := 0; i < e.blockNum; i++ {
		for j := 0; j < aes.BlockSize; j++ {
			if e.blocks[i][j] == ecb.blocks[i][j] {
				sameBytesCnt++
			}
		}
	}
	return sameBytesCnt / float64(e.blockNum*aes.BlockSize), nil
}

func (e *ECBEncrypt) PartialDecrypt(i int) error {
	if i < 0 || i >= e.blockNum {
		return errors.New("[ECBEncrypt.PartialDecrypt] index i is out of bound")
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		logrus.Error("[ECBEncrypt.PartialDecrypt] NewCipher error, err=", err)
		return err
	}
	block.Decrypt(e.blocks[i], e.blocks[i])
	return nil
}

func (e *ECBEncrypt) PartialEncrypt(i int) error {
	return nil
}
