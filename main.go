package main

import (
	"metaphrase/parsing/c"
)

func main() {
	_, f := c.BuildGraphs("/home/joey/c/esn/")
	//g.PrintNode("main.c")
	f.PrintEdges()
	f.PrintNodes(false)
}
