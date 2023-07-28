package cryptography

import (
	"AES/utli/data"
	"AES/utli/images"
	"crypto/rand"
	"io"
	"reflect"
	"sync"
	"testing"
)

func TestCBCEncrypt_GetPlaintext(t *testing.T) {
	type fields struct {
		encrypted bool
		key       []byte
		iv        []byte
		data      []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{name: "TestEncryptAndDecrypt", fields: fields{}, want: []byte("Huazhong University of Science and Technology")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := GenerateKey(16)
			iv := make([]byte, 16)
			_, _ = io.ReadFull(rand.Reader, iv)
			c := NewCBCEncrypt(tt.want, iv, key)
			err := c.Encrypt()
			if err != nil {
				t.Logf("GetPlaintext() Encrypt error = %v", err)
				return
			}
			if got := c.GetPlaintext(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPlaintext() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCBCEncrypt_PartialDecrypt(t *testing.T) {
	type fields struct {
		encrypted bool
		key       []byte
		iv        []byte
		data      []byte
	}
	type args struct {
		i int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{name: "TestPartialDecryptAccuracy", fields: fields{}, args: args{i: 0}, wantErr: false},
		{name: "TestPartialDecryptAccuracy", fields: fields{}, args: args{i: 1}, wantErr: false},
		{name: "TestPartialDecryptAccuracy", fields: fields{}, args: args{i: 2}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := GenerateKey(16)
			iv := make([]byte, 16)
			_, _ = io.ReadFull(rand.Reader, iv)
			c := NewCBCEncrypt([]byte("Huazhong University of Science and Technology"), iv, key)
			t.Logf("PartialDecrypt() block num = %d", c.GetBlockNum())
			_ = c.Encrypt()
			if err := c.PartialDecrypt(tt.args.i); (err != nil) != tt.wantErr {
				t.Errorf("PartialDecrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
			t.Logf("PartialDecrypt() block content = %v", string(c.GetHybridBlock(tt.args.i)))
		})
	}
}

func TestCBCEncrypt_CompareSimilarities(t *testing.T) {
	type fields struct {
		encrypted   bool
		key         []byte
		iv          []byte
		data        []byte
		hybridChunk []byte
	}
	type args struct {
		cbc           *CBCEncrypt
		execute       bool // 是否进行当前实验
		decryptedNum  int  // 部分解密块数
		randomByteNum int  // 随机改变字节数
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    float64
		wantErr bool
	}{
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 0, randomByteNum: 0}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 100, randomByteNum: 0}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 200, randomByteNum: 0}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 300, randomByteNum: 0}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 400, randomByteNum: 0}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 500, randomByteNum: 0}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 600, randomByteNum: 0}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 700, randomByteNum: 0}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 800, randomByteNum: 0}},

		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 0, randomByteNum: 6908}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 100, randomByteNum: 6908}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 200, randomByteNum: 6908}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 300, randomByteNum: 6908}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 400, randomByteNum: 6908}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 500, randomByteNum: 6908}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 600, randomByteNum: 6908}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 700, randomByteNum: 6908}},
		{name: "Experiment2", fields: fields{}, args: args{execute: false, decryptedNum: 800, randomByteNum: 6908}},

		{name: "Experiment2", fields: fields{}, args: args{execute: true, decryptedNum: 0, randomByteNum: 13816}},
		{name: "Experiment2", fields: fields{}, args: args{execute: true, decryptedNum: 100, randomByteNum: 13816}},
		{name: "Experiment2", fields: fields{}, args: args{execute: true, decryptedNum: 200, randomByteNum: 13816}},
		{name: "Experiment2", fields: fields{}, args: args{execute: true, decryptedNum: 300, randomByteNum: 13816}},
		{name: "Experiment2", fields: fields{}, args: args{execute: true, decryptedNum: 400, randomByteNum: 13816}},
		{name: "Experiment2", fields: fields{}, args: args{execute: true, decryptedNum: 500, randomByteNum: 13816}},
		{name: "Experiment2", fields: fields{}, args: args{execute: true, decryptedNum: 600, randomByteNum: 13816}},
		{name: "Experiment2", fields: fields{}, args: args{execute: true, decryptedNum: 700, randomByteNum: 13816}},
		{name: "Experiment2", fields: fields{}, args: args{execute: true, decryptedNum: 800, randomByteNum: 13816}},
	}
	key1, _ := GenerateKey(16)
	key2, _ := GenerateKey(16)
	iv1 := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, iv1)
	iv2 := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, iv2)
	exp1Data, err := images.LoadImage("D:\\Projects\\AES\\resource\\Ecb_encryption.png")
	if err != nil {
		t.Logf("CompareSimilarities() LoadImage error = %v", err)
		return
	}
	exp2Data := make([]byte, len(exp1Data))
	copy(exp1Data, exp2Data)
	once := sync.Once{}
	for _, tt := range tests {
		if !tt.args.execute {
			continue
		}
		if tt.args.randomByteNum != 0 {
			once.Do(func() {
				// 随机数据过程
				data.RandomChangeCntBytes(exp2Data, tt.args.randomByteNum, 256)
				sameByteCnt := float64(0)
				for i := 0; i < len(exp1Data); i++ {
					if exp1Data[i] == exp2Data[i] {
						sameByteCnt++
					}
				}
				t.Logf("origin data similarities = %v", sameByteCnt/float64(len(exp2Data)))
			})
		}
		t.Run(tt.name, func(t *testing.T) {
			c := NewCBCEncrypt(exp1Data, iv1, key1)
			if err = c.Encrypt(); err != nil {
				t.Errorf("CompareSimilarities() error = %v", err)
				return
			}
			tt.args.cbc = NewCBCEncrypt(exp2Data, iv2, key2)
			if err = tt.args.cbc.Encrypt(); err != nil {
				t.Errorf("CompareSimilarities() error = %v", err)
				return
			}
			t.Logf("blockNum: %v", c.GetBlockNum())
			t.Logf("decrypt rate: %.6f", float64(tt.args.decryptedNum)/float64(c.GetBlockNum())*100)
			for i := 0; i < tt.args.decryptedNum; i++ {
				if err = c.PartialDecrypt(i); err != nil {
					t.Errorf("CompareSimilarities() PartialDecrypt error, err = %v", err)
					return
				}
				if err = tt.args.cbc.PartialDecrypt(i); err != nil {
					t.Errorf("CompareSimilarities() PartialDecrypt error, err = %v", err)
					return
				}
			}
			got, err := c.CompareSimilarities(tt.args.cbc)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompareSimilarities() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("CompareSimilarities() got = %.6f", got*100)
		})
	}
}
