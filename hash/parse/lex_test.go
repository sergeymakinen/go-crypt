package parse

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func tokens(input string) (tokens []token) {
	l := lex(input)
	for {
		t := l.NextToken()
		tokens = append(tokens, t)
		if t.Type == tokenEOF || t.Type == tokenError {
			break
		}
	}
	return
}

func TestLex(t *testing.T) {
	tests := []struct {
		input  string
		tokens []token
	}{
		{
			input: "",
			tokens: []token{
				{Type: tokenEOF},
			},
		},
		{
			input: "$$",
			tokens: []token{
				{
					Type:  tokenError,
					Pos:   1,
					Value: "missing prefix identifier",
				},
			},
		},
		{
			input: "$prefix",
			tokens: []token{
				{
					Type:  tokenError,
					Pos:   7,
					Value: "missing prefix end",
				},
			},
		},
		{
			input: "$prefix$",
			tokens: []token{
				{
					Type:  tokenPrefix,
					Value: "$prefix$",
				},
				{
					Type: tokenEOF,
					Pos:  8,
				},
			},
		},
		{
			input: "$prefix$a$b$c=val",
			tokens: []token{
				{
					Type:  tokenPrefix,
					Value: "$prefix$",
				},
				{
					Type:  tokenValue,
					Pos:   8,
					Value: "a",
				},
				{
					Type:  tokenDollar,
					Pos:   9,
					Value: "$",
				},
				{
					Type:  tokenValue,
					Pos:   10,
					Value: "b",
				},
				{
					Type:  tokenDollar,
					Pos:   11,
					Value: "$",
				},
				{
					Type:  tokenValue,
					Pos:   12,
					Value: "c=val",
				},
				{
					Type: tokenEOF,
					Pos:  17,
				},
			},
		},
		{
			input: "$prefix$a=val,b=val",
			tokens: []token{
				{
					Type:  tokenPrefix,
					Value: "$prefix$",
				},
				{
					Type:  tokenValue,
					Pos:   8,
					Value: "a=val",
				},
				{
					Type:  tokenComma,
					Pos:   13,
					Value: ",",
				},
				{
					Type:  tokenValue,
					Pos:   14,
					Value: "b=val",
				},
				{
					Type: tokenEOF,
					Pos:  19,
				},
			},
		},
		{
			input: "$prefix$a=val,b=val,",
			tokens: []token{
				{
					Type:  tokenPrefix,
					Value: "$prefix$",
				},
				{
					Type:  tokenValue,
					Pos:   8,
					Value: "a=val",
				},
				{
					Type:  tokenComma,
					Pos:   13,
					Value: ",",
				},
				{
					Type:  tokenValue,
					Pos:   14,
					Value: "b=val",
				},
				{
					Type:  tokenComma,
					Pos:   19,
					Value: ",",
				},
				{
					Type: tokenEOF,
					Pos:  20,
				},
			},
		},
		{
			input: "_",
			tokens: []token{
				{
					Type:  tokenPrefix,
					Value: "_",
				},
				{
					Type: tokenEOF,
					Pos:  1,
				},
			},
		},
		{
			input: "_abc",
			tokens: []token{
				{
					Type:  tokenPrefix,
					Value: "_",
				},
				{
					Type:  tokenValue,
					Pos:   1,
					Value: "abc",
				},
				{
					Type: tokenEOF,
					Pos:  4,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			if diff := cmp.Diff(test.tokens, tokens(test.input)); diff != "" {
				t.Errorf("lex() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
