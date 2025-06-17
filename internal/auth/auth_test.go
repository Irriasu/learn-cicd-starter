package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectErr   bool
		errMsg      string
	}{
		{
			name:        "valid API key header",
			headers:     http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey: "my-secret-key",
			expectErr:   false,
		},
		{
			name:      "missing Authorization header",
			headers:   http.Header{},
			expectErr: true,
			errMsg:    ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:      "malformed header - missing key",
			headers:   http.Header{"Authorization": []string{"ApiKey"}},
			expectErr: true,
			errMsg:    "malformed authorization header",
		},
		{
			name:      "malformed header - wrong scheme",
			headers:   http.Header{"Authorization": []string{"Bearer something"}},
			expectErr: true,
			errMsg:    "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if err.Error() != tt.errMsg {
					t.Errorf("expected error %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if key != tt.expectedKey {
					t.Errorf("expected key %q, got %q", tt.expectedKey, key)
				}
			}
		})
	}
}

