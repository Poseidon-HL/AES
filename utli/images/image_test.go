package images

import (
	"strconv"
	"testing"
	"time"
)

const SourceImagePath = "D:\\Projects\\AES\\resource\\HUST.jpg"

func TestConvertImage(t *testing.T) {
	type args struct {
		imgByte  []byte
		filePath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "TestConvertAccuracy", args: args{
			imgByte:  nil,
			filePath: "D:\\Projects\\AES\\resource\\HUST_",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			tt.args.imgByte, err = LoadImage(SourceImagePath)
			if err != nil {
				t.Error("LoadImage error, err=", err)
				return
			}
			tt.args.filePath = tt.args.filePath + strconv.FormatInt(time.Now().Unix(), 10) + ".jpeg"
			if err = ConvertImage(tt.args.imgByte, tt.args.filePath); (err != nil) != tt.wantErr {
				t.Errorf("ConvertImage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
