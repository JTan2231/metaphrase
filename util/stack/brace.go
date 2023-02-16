package brace

type BraceStack struct {
	openBraces *int
	begin      rune
	end        rune
}

func New(begin rune, end rune) BraceStack {
	return BraceStack{openBraces: new(int), begin: begin, end: end}
}

func (bs BraceStack) EvalPush(char rune) {
	if char == bs.begin {
		(*bs.openBraces)++
	} else if (*bs.openBraces) > 0 && char == bs.end {
		(*bs.openBraces)--
	}
}

func (bs BraceStack) Len() int {
	return *bs.openBraces
}
