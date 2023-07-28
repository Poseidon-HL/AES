package data

import "testing"

func TestRandomChangeCntBytes(t *testing.T) {
	type args struct {
		src   []byte
		cnt   int
		limit int
	}
	tests := []struct {
		name string
		args args
	}{
		{name: "TestGeneratingFunction1", args: args{
			src:   nil,
			cnt:   10,
			limit: 255,
		}},
		{name: "TestGeneratingFunction2", args: args{
			src:   nil,
			cnt:   10,
			limit: 255,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			randBytes, err := GenerateRandomBytes(100)
			if err != nil {
				t.Errorf("GenerateRandomBytes() err=%v", err)
				return
			}
			tt.args.src = randBytes
			t.Log("original  bytes: ", randBytes)
			RandomChangeCntBytes(tt.args.src, tt.args.cnt, tt.args.limit)
			t.Log("processed bytes: ", randBytes)
		})
	}
}
