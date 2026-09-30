package eventconsumer

import "testing"

func TestRequestsDkls23(t *testing.T) {
	cases := map[string]struct {
		data string
		want bool
	}{
		"dkls23":         {`{"wallet_id":"w","protocol":"dkls23"}`, true},
		"tss default":    {`{"wallet_id":"w","key_type":"secp256k1"}`, false},
		"other protocol": {`{"protocol":"something-else"}`, false},
		"malformed":      {`not json`, false},
		"empty":          {``, false},
	}
	for name, tc := range cases {
		if got := requestsDkls23([]byte(tc.data)); got != tc.want {
			t.Errorf("%s: requestsDkls23 = %v, want %v", name, got, tc.want)
		}
	}
}
