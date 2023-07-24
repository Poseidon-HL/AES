package cryptography

import (
	"crypto/aes"
	"reflect"
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
