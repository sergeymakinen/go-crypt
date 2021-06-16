package parse

import (
	"fmt"
	"strings"
)

type tokenType int

const (
	tokenError tokenType = iota
	tokenPrefix
	tokenDollar
	tokenComma
	tokenValue
	tokenEOF
)

type token struct {
	Type  tokenType
	Pos   Pos
	Value string
}

type stateFn func(*lexer) stateFn

type lexer struct {
	input      string
	pos, start Pos
	tokens     chan token
}

func (l *lexer) Next() byte {
	c := l.input[l.pos]
	l.pos++
	return c
}

func (l *lexer) emit(t tokenType) {
	l.tokens <- token{
		Type:  t,
		Pos:   l.start,
		Value: l.input[l.start:l.pos],
	}
	l.start = l.pos
}

func (l *lexer) errorf(format string, args ...interface{}) stateFn {
	l.tokens <- token{
		Type:  tokenError,
		Pos:   l.pos,
		Value: fmt.Sprintf(format, args...),
	}
	return nil
}

func (l *lexer) NextToken() token {
	return <-l.tokens
}

func (l *lexer) run() {
	for state := lexPrefix; state != nil; {
		state = state(l)
	}
	close(l.tokens)
}

func lex(input string) *lexer {
	l := &lexer{
		input:  input,
		tokens: make(chan token),
	}
	go l.run()
	return l
}

const delimChars = "$,"

func lexPrefix(l *lexer) stateFn {
	if strings.HasPrefix(l.input[l.pos:], "$") {
		l.pos++
		if i := strings.IndexAny(l.input[l.pos:], delimChars); i >= 0 {
			if i == 0 {
				return l.errorf("missing prefix identifier")
			}
			l.pos += Pos(i + 1)
			l.emit(tokenPrefix)
		} else {
			l.pos = Pos(len(l.input))
			return l.errorf("missing prefix end")
		}
	}
	if strings.HasPrefix(l.input[l.pos:], "_") {
		l.pos++
		l.emit(tokenPrefix)
	}
	return lexFragment
}

func lexFragment(l *lexer) stateFn {
	if i := strings.IndexAny(l.input[l.pos:], delimChars); i >= 0 {
		l.pos += Pos(i)
		l.emit(tokenValue)
		switch l.Next() {
		case '$':
			l.emit(tokenDollar)
		case ',':
			l.emit(tokenComma)
		}
		return lexFragment
	}
	l.pos = Pos(len(l.input))
	if l.pos > l.start {
		l.emit(tokenValue)
	}
	l.emit(tokenEOF)
	return nil
}
