package cryptography

import (
	"crypto/rand"
	"io"
	"reflect"
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
