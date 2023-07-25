package file

import (
	"AES/utli/images"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"strconv"
	"time"
)

// LoadFile2Image 加载字节流数据并转换输出图片
func LoadFile2Image(fileName string) error {
	fileBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		logrus.Error("[LoadFile2Image] ReadFile error, err=", err)
		return err
	}
	filePath := strconv.FormatInt(time.Now().Unix(), 10) + ".png"
	err = images.ConvertImage(fileBytes, filePath)
	if err != nil {
		logrus.Error("[LoadFile2Image] ConvertImage error, err=", err)
		return err
	}
	return nil
}
