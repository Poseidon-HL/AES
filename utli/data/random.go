package data

import (
	"crypto/rand"
	"github.com/sirupsen/logrus"
	"io"
	"math/big"
)

func GenerateRandomBytes(length int) ([]byte, error) {
	randBytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, randBytes); err != nil {
		logrus.Error("[GenerateRandomBytes] ReadFull error, err=", err)
		return nil, err
	}
	return randBytes, nil
}

func RandomChangeCntBytes(src []byte, cnt, limit int) {
	idx := make([]int, 0)
	for i := 0; i < cnt; i++ {
		rInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(src))))
		idx = append(idx, int(rInt.Int64()))
	}
	for i := 0; i < len(idx); i++ {
		rByte, _ := rand.Int(rand.Reader, big.NewInt(int64(limit)))
		src[idx[i]] = byte(rByte.Int64())
	}
}
