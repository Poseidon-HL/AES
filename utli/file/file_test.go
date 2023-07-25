package file

import "testing"

func TestLoadFile2Image(t *testing.T) {
	type args struct {
		fileName string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "TestPlaintextImage", args: args{fileName: "D:\\Projects\\AES\\resource\\bytes.txt"}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := LoadFile2Image(tt.args.fileName); (err != nil) != tt.wantErr {
				t.Errorf("LoadFile2Image() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
