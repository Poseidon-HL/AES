package handler

import (
	"AES/utli/cryptography"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

// GetFile 从server获取文件，若选择加密，则文件内容将以加密形式传输 fileName传输文件路径
func GetFile(c *gin.Context) {
	fileName := QueryStringByDefault(c, "fileName", "")
	encrypted := QueryBoolByDefault(c, "encrypted", false)
	key := QueryStringByDefault(c, "key", "")
	keyByte := make([]byte, 0)
	fileBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		logrus.Error("[GetFile] ReadFile error, err=", err)
		c.JSON(http.StatusOK, Resp{
			ErrMsg: err.Error(),
		})
		return
	}
	if encrypted {
		if len(key) == 0 {
			keyByte, err = cryptography.GenerateKey(16)
			if err != nil {
				logrus.Error("[GetFile] GenerateKey error, err=", err)
				c.JSON(http.StatusOK, Resp{
					ErrMsg: err.Error(),
				})
				return
			}
		} else {
			keyByte = []byte(key)
		}
		fileBytes, err = cryptography.EncryptAESByECB(keyByte, fileBytes)
		if err != nil {
			logrus.Error("[GetFile] EncryptAESByCBC error, err=", err)
			c.JSON(http.StatusOK, Resp{
				ErrMsg: err.Error(),
			})
			return
		}
	}
	c.Writer.Header().Set("key", string(key))
	_, err = c.Writer.Write(fileBytes)
	if err != nil {
		logrus.Error("[GetFile] Write error, err=", err)
		c.JSON(http.StatusOK, Resp{
			ErrMsg: err.Error(),
		})
		return
	}
	return
}

// GetEncryptedFile 获取加密字节流的数据信息，需要保证key的一致性
func GetEncryptedFile(c *gin.Context) {
	fileName := QueryStringByDefault(c, "fileName", "")
	key := QueryStringByDefault(c, "key", "")
	fileBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		logrus.Error("[GetEncryptedFile] ReadFile error, err=", err)
		c.JSON(http.StatusOK, Resp{ErrMsg: err.Error()})
		return
	}
	fileBytes, err = cryptography.DecryptAESByECB([]byte(key), fileBytes)
	if err != nil {
		c.JSON(http.StatusOK, Resp{ErrMsg: err.Error()})
		return
	}
	if _, err = c.Writer.Write(fileBytes); err != nil {
		c.JSON(http.StatusOK, Resp{ErrMsg: err.Error()})
		return
	}
	c.JSON(http.StatusOK, Resp{Data: "success"})
	return
}
