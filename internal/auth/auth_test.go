package auth_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headerKey   string
		headerValue string
		want        string
		wantErr     string
	}{
		{
			name:    "Missing header",
			wantErr: "no authorization header",
		},
		{
			name:      "Missing key",
			headerKey: "Authorization",
			wantErr:   "no authorization header",
		},
		{
			name:        "Malformed Header",
			headerKey:   "Authorization",
			headerValue: "-",
			wantErr:     "malformed authorization header",
		},
		{
			name:        "Malformed long Header",
			headerKey:   "Authorization",
			headerValue: "Bearer xxxxxx",
			wantErr:     "malformed authorization header",
		},
		{
			name:        "Working Header",
			headerKey:   "Authorization",
			headerValue: "ApiKey xxxxxx",
			want:        "xxxxxx",
			wantErr:     "not expecting an error",
		},
		{
			name:        "Force error",
			headerKey:   "Authorization",
			headerValue: "Bearer xxxxx",
			want:        "xxxxx",
			wantErr:     "Expecting an Error, but this shouldn't catch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			header.Add(tt.headerKey, tt.headerValue)
			got, gotErr := auth.GetAPIKey(header)
			if gotErr != nil {
				if strings.Contains(gotErr.Error(), tt.wantErr) {
					return
				}
				t.Errorf("Unexpcted: %v\n", gotErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetAPIKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
