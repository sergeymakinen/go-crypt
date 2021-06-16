package parse

import "strconv"

// NodeType identifies the type of a parse tree node.
type NodeType int

func (t NodeType) String() string {
	switch t {
	case NodePrefix:
		return "prefix"
	case NodeGroup:
		return "group"
	case NodeValue:
		return "value"
	default:
		return "unknown type: " + strconv.Itoa(int(t))
	}
}

const (
	NodePrefix NodeType = iota
	NodeGroup
	NodeValue
)

// Pos represents a byte position in the original input text.
type Pos int

// Node is an element in the parse tree.
// The interface contains an unexported method so that only
// types local to this package can satisfy it.
type Node interface {
	Type() NodeType
	String() string
	Pos() Pos // position of first byte belonging to the node
	End() Pos // position of first byte immediately after the node
	node()
}

// PrefixNode holds a hash prefix, like '_', '$id$' or '$id,'.
type PrefixNode struct {
	Text string
	end  Pos
}

func (p *PrefixNode) Type() NodeType { return NodePrefix }
func (p *PrefixNode) String() string { return p.Text }
func (p *PrefixNode) Pos() Pos       { return 0 }
func (p *PrefixNode) End() Pos       { return p.end }

func (p *PrefixNode) node() {}

// FragmentNode represents a fragment separated by '$'.
type FragmentNode interface {
	Node
	fragmentNode()
}

// ValueNode holds a single value.
type ValueNode struct {
	Value    string
	pos, end Pos
}

func (v *ValueNode) Type() NodeType { return NodeValue }
func (v *ValueNode) String() string { return v.Value }
func (v *ValueNode) Pos() Pos       { return v.pos }
func (v *ValueNode) End() Pos       { return v.end }

func (v *ValueNode) node()         {}
func (v *ValueNode) fragmentNode() {}

// GroupNode represents a comma-separated list of values.
type GroupNode struct {
	Values []*ValueNode // len(Values) > 0
}

func (g *GroupNode) Type() NodeType { return NodeGroup }
func (g *GroupNode) String() string { return "" }
func (g *GroupNode) Pos() Pos       { return g.Values[0].Pos() }
func (g *GroupNode) End() Pos       { return g.Values[len(g.Values)-1].End() }

func (g *GroupNode) node()         {}
func (g *GroupNode) fragmentNode() {}

// Tree is the representation of a single parsed hash.
type Tree struct {
	Prefix    *PrefixNode
	Fragments []FragmentNode
}
