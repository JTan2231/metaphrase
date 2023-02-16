package main

import (
	"metaphrase/parsing/c"
)

func main() {
	_, f := c.BuildGraphs("/home/joey/c/git/")
	//g.PrintNode("main.c")
	f.PrintNodes(false)
	f.PrintCounts()
}
