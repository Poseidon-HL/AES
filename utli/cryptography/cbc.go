package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/sirupsen/logrus"
	"github.com/zenazn/pkcs7pad"
)

type CBCEncrypt struct {
	encrypted   bool   // 是否加密
	key         []byte // 加解密密钥
	iv          []byte // 初始向量
	data        []byte // 数据块，通过特定的下标访问不同的块数据
	hybridChunk []byte // 由于CBC特性，需要一直保留这一信息
}

func NewCBCEncrypt(plaintext, iv, key []byte) *CBCEncrypt {
	if len(iv) != aes.BlockSize {
		logrus.Error("[NewCBCEncrypt] error, iv size must equal to block size")
		return nil
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		logrus.Error("[NewCBCEncrypt] error, key length is not correct")
		return nil
	}
	c := CBCEncrypt{
		key: key,
		iv:  iv,
	}
	// 将plaintext进行补全对齐后再存储
	c.data = pkcs7pad.Pad(plaintext, aes.BlockSize)
	return &c
}

// Encrypt CBC加密，需要依赖IV，且加密过程需要串行执行（后以块依赖于前一块的加密结果）
func (c *CBCEncrypt) Encrypt() error {
	if c.encrypted {
		return nil
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		logrus.Error("[CBCEncrypt.Encrypt] NewCipher error, err=", err)
		return err
	}
	// 进行整段的加密
	mode := cipher.NewCBCEncrypter(block, c.iv)
	mode.CryptBlocks(c.data, c.data)
	c.encrypted = true
	c.hybridChunk = make([]byte, len(c.data)) // data将永远存储明文数据或密文数据
	copy(c.hybridChunk, c.data)
	return nil
}

// Decrypt CBC解密，这一方法将对全部数据进行解密
func (c *CBCEncrypt) Decrypt() error {
	if !c.encrypted {
		return nil
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		logrus.Error("[CBCEncrypt.Decrypt] NewCipher error, err=", err)
		return err
	}
	mode := cipher.NewCBCDecrypter(block, c.iv)
	mode.CryptBlocks(c.data, c.data)
	c.encrypted = false
	return nil
}

func (c *CBCEncrypt) GetPlaintext() []byte {
	if !c.encrypted {
		return c.data
	}
	_ = c.Decrypt()
	plaintext, _ := pkcs7pad.Unpad(c.data)
	return plaintext
}

// PartialDecrypt CBC部分解密，CBC解密过程只需要前一数据块，但是partial的问题在于解密后的数据块需要单独存储
func (c *CBCEncrypt) PartialDecrypt(i int) error {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		logrus.Error("[CBCEncrypt.PartialDecrypt] NewCipher error, err=", err)
		return err
	}
	preBlock := c.GetBlock(i - 1)
	curBlock := c.GetHybridBlock(i)
	mode := cipher.NewCBCDecrypter(block, preBlock)
	mode.CryptBlocks(curBlock, curBlock)
	return nil
}

func (c *CBCEncrypt) GetHybridBlock(i int) []byte {
	if i < 0 || i > c.GetBlockNum() {
		return nil
	}
	return c.hybridChunk[i*aes.BlockSize : (i+1)*aes.BlockSize]
}

func (c *CBCEncrypt) GetBlock(i int) []byte {
	if i == -1 {
		return c.iv
	}
	if i < 0 || i > c.GetBlockNum() {
		return nil
	}
	return c.data[i*aes.BlockSize : (i+1)*aes.BlockSize]
}

func (c *CBCEncrypt) GetBlockNum() int {
	return len(c.data) / aes.BlockSize
}

func (c *CBCEncrypt) IsEncrypted() bool {
	return c.encrypted
}
