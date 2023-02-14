package graphs

import (
	"fmt"
	"log"
	"metaphrase/util/shorthand"
	"metaphrase/util/stack"
	"strings"
)

type functionNode struct {
	Filename        string
	Signature       string
	Name            string
	Definition      []string
	DefinitionLine  int
	DeclarationLine int
}

type FunctionGraph struct {
	Functions map[string]*functionNode
	Edges     map[string][]*functionNode
}

func NewFunctionGraph() FunctionGraph {
	return FunctionGraph{
		Functions: make(map[string]*functionNode),
		Edges:     make(map[string][]*functionNode),
	}
}

func nameFromSignature(signature string) string {
	var name string
	i := 0
	for i < len(signature) && signature[i] != '(' {
		name += string(signature[i])
		i++
	}

	split := strings.Split(name, " ")
	name = split[len(split)-1] // take functionName from e.g. { int functionName() }

	return name
}

// TODO: only assumes the functions are structured like
//
//		void functionName(type args) {
//
//		need(?) to accommodate formats like
//		    void
//		    functionName(type args)
//		    {
//
//	     i.e. this could be much more generalized
//
// add a new function to the graph
// returns the parsed name of the function and a list of other functions it calls in its body
func (g FunctionGraph) RegisterFunction(filename string, fileContent []string, functionStart int) (string, []string) {
	var functionSignature string
	firstLine := fileContent[functionStart]
	braceStack := brace.New()
	for _, char := range firstLine {
		if char != '{' {
			functionSignature += string(char)
		}

		braceStack.EvalPush(char)
	}

	functionSignature = functionSignature[:len(functionSignature)-1]
	functionName := nameFromSignature(functionSignature)

	if functionName == `cmv_decode_intra` {
		fmt.Println(firstLine)
	}

	var functionEnd int
	var functionDefinition []string

	functionCalls := make([]string, 0)

	if braceStack.Len() > 0 {
		// TODO: write a better regex or replace this with a proper parser
		functionCallRegex := shorthand.MakeRegex(`(\w\d_)+\((.*?)\)`)
		functionEnd = functionStart + 1

		for braceStack.Len() > 0 {
			line := fileContent[functionEnd]
			callLine := functionCallRegex.FindStringSubmatch(line)

			// log name of called function
			if callLine != nil {
				var call string
				i := 0
				for i < len(callLine[0]) && callLine[0][i] != '(' {
					call += string(callLine[0][i])
					i++
				}

				functionCalls = append(functionCalls, call)
			}

			// determine whether we're changing scope
			for _, char := range line {
				braceStack.EvalPush(char)
			}

			functionEnd++
		}

		functionDefinition = fileContent[functionStart:functionEnd]
	}

	g.Functions[functionName] = &functionNode{
		Filename:        filename,
		Signature:       functionSignature,
		Name:            functionName,
		Definition:      functionDefinition,
		DefinitionLine:  functionStart,
		DeclarationLine: functionStart,
	}

	return functionName, functionCalls
}

func (g FunctionGraph) AddEdge(from string, to string) {
	if node, ok := g.Functions[to]; ok {
		if edge, ok := g.Edges[from]; ok {
			for _, v := range edge {
				if v.Name == to {
					return
				}
			}

			edge = append(edge, node)
			g.Edges[from] = edge
		} else {
			g.Edges[from] = []*functionNode{node}
		}
	} else {
		log.Fatal("function_graph: function " + to + " does not exist in this graph")
	}
}

func (g FunctionGraph) PrintNodes(verbose bool) {
	for filename, node := range g.Functions {
		fmt.Println("function name: " + filename)
		//fmt.Println("function signature: " + node.Signature)

		if verbose {
			for lineNumber, line := range node.Definition {
				fmt.Println(fmt.Sprint(lineNumber) + ": " + line)
			}
		}

		//fmt.Println("----------------------")
	}

	fmt.Printf("printed %v functions\n", len(g.Functions))
}

func (g FunctionGraph) PrintEdges() {
	for from := range g.Edges {
		node := g.Functions[from]
		for _, to := range g.Edges[from] {
			fmt.Printf("%s -> %s\n", node.Name, to.Name)
		}

		fmt.Println("------------")
	}
}

func (g FunctionGraph) PrintCounts() {
	fmt.Printf("%v functions; %v edges\n", len(g.Functions), len(g.Edges))
}

func (g FunctionGraph) PrintNode(function string) {
	fmt.Println("printing function " + function)
	if node, ok := g.Functions[function]; ok {
		for _, to := range g.Edges[function] {
			fmt.Printf("%s -> %s\n", node.Name, to.Name)
		}
	} else {
		fmt.Println("error: couldn't find " + function)
	}

	fmt.Println("------------")
}
