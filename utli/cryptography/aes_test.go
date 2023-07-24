package cryptography

import (
	"reflect"
	"testing"
)

func TestEncryptAES(t *testing.T) {
	type args struct {
		key       []byte
		plaintext []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{name: "TestLengthLessThanBlockSize", args: args{
			key:       nil,
			plaintext: nil,
		}, want: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := GenerateKeyByString([]byte("This is secret key"), 8)
			tt.args.key = key
			got, err := EncryptAES(tt.args.key, tt.args.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptAES() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EncryptAES() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncryptAESByCBC(t *testing.T) {
	type args struct {
		key       []byte
		plaintext []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{name: "TestEncrypt", args: args{
			key:       nil,
			plaintext: []byte("Welcome to Huazhong University of Science and Technology ......."),
		}, want: []byte(""), wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := GenerateKeyByString([]byte("password"), 16)
			tt.args.key = key
			_, err := EncryptAESByCBC(tt.args.key, tt.args.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptAESByCBC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestDecryptAESByCBC(t *testing.T) {
	type args struct {
		key        []byte
		ciphertext []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{name: "TestEncryptAndDecrypt", args: args{
			key:        nil,
			ciphertext: nil,
		}, want: []byte("Welcome to Huazhong University of Science and Technology ......."), wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := GenerateKeyByString([]byte("password"), 16)
			tt.args.key = key
			tt.args.ciphertext, _ = EncryptAESByCBC(key, tt.want)
			got, err := DecryptAESByCBC(tt.args.key, tt.args.ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptAESByCBC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecryptAESByCBC() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecryptAESByECB(t *testing.T) {
	type args struct {
		key        []byte
		ciphertext []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{name: "TestDecryptCorrectness", args: args{
			key:        nil,
			ciphertext: nil,
		}, want: []byte("Welcome to Huazhong University of Science and Technology ......."), wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			tt.args.key, _ = GenerateKey(16)
			tt.args.ciphertext, err = EncryptAESByECB(tt.args.key, tt.want)
			got, err := DecryptAESByECB(tt.args.key, tt.args.ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptAESByECB() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecryptAESByECB() got = %v, want %v", got, tt.want)
			}
		})
	}
}
