package cryptography

import (
	"testing"
)

func TestGenerateKey(t *testing.T) {
	type args struct {
		keyLen int
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{name: "TestGenerateKeys_1", args: args{keyLen: 16}, want: nil, wantErr: false},
		{name: "TestGenerateKeys_2", args: args{keyLen: 16}, want: nil, wantErr: false},
		{name: "TestGenerateKeys_3", args: args{keyLen: 16}, want: nil, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateKey(tt.args.keyLen)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Log(got)
		})
	}
}
