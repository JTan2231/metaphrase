package main

import (
	"metaphrase/openai"
	"metaphrase/parsing/c"
)

func main() {
	_, f := c.BuildGraphs("/home/joey/c/esn/")

	openai.CompletionAPICall("matDot", &f)
}
