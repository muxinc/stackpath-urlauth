package urlauth

import (
	"testing"
	"time"
)

var (
	expirationTime = time.Unix(1544720086, 0)
)

func TestSignURL(t *testing.T) {
	type args struct {
		url            string
		secret         string
		expirationTime *time.Time
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "Empty URL",
			args:    args{},
			wantErr: true,
		},
		{
			name:    "Empty secret",
			args:    args{url: "https://www.example.com/foo"},
			wantErr: true,
		},
		{
			name: "Invalid URL",
			args: args{
				url:    "*&#$%",
				secret: "supersecret",
			},
			wantErr: true,
		},
		{
			name: "Valid URL without an expiration time",
			args: args{
				url:    "https://www.example.com/foo?client_id=abc123",
				secret: "supersecret",
			},
			wantErr: true,
		},
		{
			name: "Valid URL with a query param",
			args: args{
				url:            "https://www.example.com/foo?bar=1",
				secret:         "supersecret",
				expirationTime: &expirationTime,
			},
			want: "https://www.example.com/foo?bar=1&st=Uj93Ort3Xu6UYeIovupeUA&e=1544720086",
		},
		{
			name: "Valid URL without a query-param",
			args: args{
				url:            "https://www.example.com/foo",
				secret:         "supersecret",
				expirationTime: &expirationTime,
			},
			want: "https://www.example.com/foo?st=Uj93Ort3Xu6UYeIovupeUA&e=1544720086",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignURL(tt.args.url, tt.args.secret, tt.args.expirationTime)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
