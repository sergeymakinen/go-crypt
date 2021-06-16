// Package parse builds parse trees for crypt(3) hashes.
//
// Supported schemes:
//	- DES: <value>(<value>)*
//	- DES Extended (BSDi): _<value>(<value>)*
//	- MCF/PHC: $<id>$fragment($<fragment>)*
//	Where:
//	 - <fragment> is (<group>|<param>=<value>|<value>)
//	 - <group> is <param>=<value>,<param>=<value>(,<param>=<value>)*
package parse

// SyntaxError suggests that the hash is invalid.
type SyntaxError struct {
	Offset int    // byte offset in input where error was detected
	Msg    string // description of error
}

func (e *SyntaxError) Error() string { return e.Msg }

// Parse parses the hash string and returns the corresponding syntax tree.
func Parse(hash string) (*Tree, error) {
	tree := &Tree{}
	l := lex(hash)
	var (
		group *GroupNode
		value *ValueNode
	)
Loop:
	for {
		t := l.NextToken()
		switch t.Type {
		case tokenError:
			return nil, &SyntaxError{
				Offset: int(t.Pos),
				Msg:    t.Value,
			}
		case tokenPrefix:
			tree.Prefix = &PrefixNode{
				Text: t.Value,
				end:  Pos(len(t.Value)),
			}
		case tokenDollar, tokenEOF:
			if value != nil {
				if group != nil {
					group.Values = append(group.Values, value)
					tree.Fragments = append(tree.Fragments, group)
					group = nil
				} else {
					tree.Fragments = append(tree.Fragments, value)
				}
				value = nil
			}
			if t.Type == tokenEOF {
				break Loop
			}
		case tokenComma:
			if group == nil {
				group = &GroupNode{}
			}
			group.Values = append(group.Values, value)
			value = nil
		case tokenValue:
			value = &ValueNode{
				Value: t.Value,
				pos:   t.Pos,
				end:   t.Pos + Pos(len(t.Value)),
			}
		}
	}
	return tree, nil
}
