package brace

type BraceStack struct {
	openBraces *int
}

func New() BraceStack {
	return BraceStack{openBraces: new(int)}
}

func (bs BraceStack) EvalPush(char rune) {
	if char == '{' {
		(*bs.openBraces)++
	} else if (*bs.openBraces) > 0 && char == '}' {
		(*bs.openBraces)--
	}
}

func (bs BraceStack) Len() int {
	return *bs.openBraces
}
