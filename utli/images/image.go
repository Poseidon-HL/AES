package images

import (
	"bufio"
	"bytes"
	"github.com/sirupsen/logrus"
	"image"
	"image/jpeg"
	"io"
	"os"
)

func LoadImage(filepath string) ([]byte, error) {
	input, _ := os.Open(filepath)
	defer func() {
		if err := input.Close(); err != nil {
			logrus.Error("[LoadImage] Close error, err=", err)
		}
	}()
	stat, err := input.Stat()
	if err != nil {
		logrus.Error("[LoadImage] Get file stat error, err=", err)
		return nil, err
	}

	buffer := make([]byte, stat.Size())
	_, err = bufio.NewReader(input).Read(buffer)
	if err != nil && err != io.EOF {
		logrus.Error("[LoadImage] Read file error, err=", err)
		return nil, err
	}
	return buffer, nil
}

func ConvertImage(imgByte []byte, filePath string) error {
	img, _, err := image.Decode(bytes.NewReader(imgByte))
	if err != nil {
		logrus.Error("[ConvertImage] Decode error, err=", err)
		return err
	}
	out, _ := os.Create(filePath)
	defer func() {
		if err = out.Close(); err != nil {
			logrus.Error("[ConvertImage] Close error, err=", err)
		}
	}()
	err = jpeg.Encode(out, img, nil)
	if err != nil {
		logrus.Error("[ConvertImage] Encode error, err=", err)
		return err
	}
	return nil
}
