package parse

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sergeymakinen/go-crypt/internal/testutil"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input string
		tree  *Tree
		err   error
	}{
		{
			input: "",
			tree:  &Tree{},
		},
		{
			input: "$$",
			err: &SyntaxError{
				Offset: 1,
				Msg:    "missing prefix identifier",
			},
		},
		{
			input: "$prefix",
			err: &SyntaxError{
				Offset: 7,
				Msg:    "missing prefix end",
			},
		},
		{
			input: "$prefix$",
			tree: &Tree{Prefix: &PrefixNode{
				Text: "$prefix$",
				end:  8,
			}},
		},
		{
			input: "$prefix$a$b$c=val,d=val,e$f",
			tree: &Tree{
				Prefix: &PrefixNode{
					Text: "$prefix$",
					end:  8,
				},
				Fragments: []FragmentNode{
					&ValueNode{
						Value: "a",
						pos:   8,
						end:   9,
					},
					&ValueNode{
						Value: "b",
						pos:   10,
						end:   11,
					},
					&GroupNode{Values: []*ValueNode{
						{
							Value: "c=val",
							pos:   12,
							end:   17,
						},
						{
							Value: "d=val",
							pos:   18,
							end:   23,
						},
						{
							Value: "e",
							pos:   24,
							end:   25,
						},
					}},
					&ValueNode{
						Value: "f",
						pos:   26,
						end:   27,
					},
				},
			},
		},
		{
			input: "_",
			tree: &Tree{Prefix: &PrefixNode{
				Text: "_",
				end:  1,
			}},
		},
		{
			input: "_abc",
			tree: &Tree{
				Prefix: &PrefixNode{
					Text: "_",
					end:  1,
				},
				Fragments: []FragmentNode{&ValueNode{
					Value: "abc",
					pos:   1,
					end:   4,
				}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			tree, err := Parse(test.input)
			if !testutil.IsEqualError(err, test.err) {
				t.Errorf("Parse() = _, %v; want %v", err, test.err)
			}
			if diff := cmp.Diff(test.tree, tree, cmp.AllowUnexported(PrefixNode{}, ValueNode{})); diff != "" {
				t.Errorf("Parse() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
