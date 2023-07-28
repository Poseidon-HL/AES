package cryptography

import (
	"AES/utli/data"
	"AES/utli/images"
	"crypto/aes"
	"reflect"
	"sync"
	"testing"
)

func TestECBEncrypt_GetPlainText(t *testing.T) {
	type fields struct {
		blockNum  int
		encrypted bool
		key       []byte
		blocks    [][]byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{name: "TestGetPlainTextCorrectness", fields: fields{
			blockNum:  0,
			encrypted: false,
			key:       nil,
			blocks:    nil,
		}, want: []byte("Huazhong University of Science and Technology")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ECBEncrypt{}
			key, _ := GenerateKey(aes.BlockSize)
			e.Load(tt.want, key)
			if got := e.GetPlainText(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPlainText() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestECBEncrypt_GetCipherText(t *testing.T) {
	type fields struct {
		blockNum  int
		encrypted bool
		key       []byte
		blocks    [][]byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{name: "TestGetPlainTextCorrectness", fields: fields{
			blockNum:  0,
			encrypted: false,
			key:       nil,
			blocks:    nil,
		}, want: []byte("Huazhong University of Science and Technology")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ECBEncrypt{}
			key, _ := GenerateKey(aes.BlockSize)
			e.Load(tt.want, key)
			_ = e.GetCipherText()
			e.GetPlainText()
			if got := e.GetPlainText(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPlainText() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestECBEncrypt_GetPlainBlock(t *testing.T) {
	type fields struct {
		blockNum  int
		encrypted bool
		key       []byte
		blocks    [][]byte
	}
	type args struct {
		i int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []byte
	}{
		{name: "TestGetBlocks", fields: fields{
			blockNum:  0,
			encrypted: false,
			key:       nil,
			blocks:    nil,
		}, args: args{i: 0}, want: []byte("Huazhong University of Science and Technology")},
		{name: "TestGetBlocks", fields: fields{
			blockNum:  0,
			encrypted: false,
			key:       nil,
			blocks:    nil,
		}, args: args{i: 1}, want: []byte("Huazhong University of Science and Technology")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ECBEncrypt{}
			key, _ := GenerateKey(aes.BlockSize)
			err := e.Load(tt.want, key).Encrypt()
			if err != nil {
				t.Errorf("GetPlainBlock() err=%v", err)
			}
			t.Log(string(e.GetPlainBlock(tt.args.i)))
		})
	}
}

func TestECBEncrypt_PartialDecrypt(t *testing.T) {
	type fields struct {
		blockNum          int
		encrypted         bool
		key               []byte
		blocks            [][]byte
		encryptedBlockNum int
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
		{name: "TestUsingPartialDecrypt2DecryptAllChunks", fields: fields{}, args: args{i: 0}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := GenerateKey(16)
			e := &ECBEncrypt{}
			if err := e.Load([]byte("Huazhong University of Science and Technology"), key).Encrypt(); err != nil {
				t.Errorf("PartialDecrypt() error = %v", err)
				return
			}
			if err := e.PartialDecrypt(tt.args.i); (err != nil) != tt.wantErr {
				t.Errorf("PartialDecrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
			t.Log(string(e.GetBlock(tt.args.i)))
		})
	}
}

// 测试密文明文混合相似度实验
func TestECBEncrypt_CompareSimilarities(t *testing.T) {
	type fields struct {
		blockNum          int
		encrypted         bool
		key               []byte
		blocks            [][]byte
		isExperiment      bool
		encryptedBlockNum int
	}
	type args struct {
		ecb           *ECBEncrypt
		execute       bool // 是否执行当前组别实验
		decryptedNum  int  // 添加字段，进行部分解密
		randomByteNum int  // 随机改变的字节数目
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    float64
		wantErr bool
	}{
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 100, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 200, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 300, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 400, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 500, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 600, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 700, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 800, execute: false}},

		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 100, randomByteNum: 6908, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 200, randomByteNum: 6908, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 300, randomByteNum: 6908, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 400, randomByteNum: 6908, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 500, randomByteNum: 6908, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 600, randomByteNum: 6908, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 700, randomByteNum: 6908, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 800, randomByteNum: 6908, execute: false}},

		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 100, randomByteNum: 13816, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 200, randomByteNum: 13816, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 300, randomByteNum: 13816, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 400, randomByteNum: 13816, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 500, randomByteNum: 13816, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 600, randomByteNum: 13816, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 700, randomByteNum: 13816, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 800, randomByteNum: 13816, execute: false}},

		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 100, randomByteNum: 20724, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 200, randomByteNum: 20724, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 300, randomByteNum: 20724, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 400, randomByteNum: 20724, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 500, randomByteNum: 20724, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 600, randomByteNum: 20724, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 700, randomByteNum: 20724, execute: false}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 800, randomByteNum: 20724, execute: false}},

		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 100, randomByteNum: 27632, execute: true}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 200, randomByteNum: 27632, execute: true}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 300, randomByteNum: 27632, execute: true}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 400, randomByteNum: 27632, execute: true}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 500, randomByteNum: 27632, execute: true}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 600, randomByteNum: 27632, execute: true}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 700, randomByteNum: 27632, execute: true}},
		{name: "TestCompareSimilarities", fields: fields{}, args: args{ecb: &ECBEncrypt{}, decryptedNum: 800, randomByteNum: 27632, execute: true}},
	}
	key1, _ := GenerateKey(16)
	key2, _ := GenerateKey(16)
	exp1Data, err := images.LoadImage("D:\\Projects\\AES\\resource\\Ecb_encryption.png")
	if err != nil {
		t.Errorf("CompareSimilarities() LoadImage error = %v", err)
		return
	}
	exp2Data := make([]byte, len(exp1Data))
	copy(exp2Data, exp1Data)
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
			e := &ECBEncrypt{}
			if err = e.Load(exp1Data, key1).Encrypt(); err != nil {
				t.Errorf("CompareSimilarities() Load e error = %v", err)
				return
			}

			if err = tt.args.ecb.Load(exp2Data, key2).Encrypt(); err != nil {
				t.Errorf("CompareSimilarities() Load ecb error = %v", err)
				return
			}
			t.Logf("blockNum: %v", e.blockNum)
			t.Logf("decrypt rate: %.6f", float64(tt.args.decryptedNum)/float64(e.blockNum)*100)
			got, err := e.CompareSimilarities(tt.args.ecb)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompareSimilarities() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("origin similarities: %.6f", got*100)
			for i := 0; i < tt.args.decryptedNum; i++ {
				_ = e.PartialDecrypt(i)
				_ = tt.args.ecb.PartialDecrypt(i)
			}
			got, err = e.CompareSimilarities(tt.args.ecb)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompareSimilarities() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("encrypted similarities: %.6f", got*100)
		})
	}
}
