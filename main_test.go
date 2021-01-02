package main

import (
	"encoding/hex"
	"testing"
)

func TestGetPttIPConnectionData(t *testing.T) {
	type Input struct {
		ipPortString string
		localPort    uint16
		flag         uint32
	}
	type TestCase struct {
		input    Input
		expected string
	}

	cases := []TestCase{
		{
			input: Input{
				ipPortString: "1.2.3.4:5678",
				localPort:    8899,
				flag:         1,
			},
			expected: "240000000000000004000000010203040000000000000000000000002e16c32201000000",
		},
		{
			input: Input{
				ipPortString: "1.2.3.5:5678",
				localPort:    8899,
				flag:         1,
			},
			expected: "240000000000000004000000010203050000000000000000000000002e16c32201000000",
		},
		{
			input: Input{
				ipPortString: "[0102:0304:0506:0708:090a:0b0c:0d0e:0f10]:255",
				localPort:    16,
				flag:         1,
			},
			expected: "2400000000000000100000000102030405060708090a0b0c0d0e0f10ff00100001000000",
		},
	}

	for i, c := range cases {

		actual := getPttIPConnectionData(c.input.ipPortString, c.input.localPort, c.input.flag)
		if hex.EncodeToString(actual) != c.expected {
			t.Errorf("result on index: %d not match, want: %v, got: %v", i, c.expected, hex.EncodeToString(actual))
		}

	}

}
