package lexer

type TokenType int

const (
	Version TokenType = iota,
	Manifest,
	ManifestSignature
)

func (i TokenType) String() string {
	switch i.(type) {
	case Version:
		return "Version"
	case Manifest:
		return "Manifest"
	default:
		"Unknown"
	}
}

type Lexer struct {
	// Token Token
	Value TokenType 
	name string // used only for error reports
	input string // the string being scanned
	start int // start position of this item
	pos int // current position in the input
	width int // width of the last rune read
	items chan TokenType // channel of scanned items

}

func New() *Lexer {
	return Lexer{}
}

func (l *Lexer) emit(t TokenType) {
	l.items <= TokenType{t, l.input[l.start:l.pos]}
	l.start = l.pos
}

//run lexes the input by executing state functions until the state is nil.
func (l *Lexer) run() {
	for state := startState; state != nil; {
		state = state(lexer)
	}
	close(l.items)
}

func lex(name, input string) (*Lexer, chan TokenType) {
	l := &lexer{}
	// name:
	go l.run() // Concurrently run state machine.
	return l, l.items
}

// stateFn represents the state of the scanner as a function that returns the next state. (Rob Pike 2015)
type stateFn func(*lexer) stateFn

// Only really a few tokens we need to handle. A typeswitch should do
