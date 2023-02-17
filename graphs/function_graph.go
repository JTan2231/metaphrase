package graphs

import (
	"fmt"
	"log"
	"strings"
)

type Function struct {
	Filename   string
	Signature  string
	Name       string
	Definition []string
	Calls      map[string]bool
}

type functionNode struct {
	Filename        string
	Signature       string
	Name            string
	Definition      []string
	DefinitionLine  int
	DeclarationLine int
}

type FunctionGraph struct {
	Functions    map[string]*functionNode
	Edges        map[string][]*functionNode
	edgeQueueSet map[string]bool // probably needs a better name
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

// accepts a function object, which includes
// the nodes outgoing edges
func (g FunctionGraph) AddFunction(f Function) {
	if _, ok := g.Functions[f.Name]; !ok {
		g.Functions[f.Name] = &functionNode{
			Name:       f.Name,
			Filename:   f.Filename,
			Signature:  f.Signature,
			Definition: f.Definition,
		}

		for call := range f.Calls {
			if node, ok := g.Functions[call]; ok {
				if edge, ok := g.Edges[f.Name]; ok {
					edge = append(edge, node)
					g.Edges[f.Name] = edge
				} else {
					g.Edges[f.Name] = []*functionNode{node}
				}
			}
		}
	}
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

func (g FunctionGraph) GetEdges(from string) []*functionNode {
	if edges, ok := g.Edges[from]; ok {
		return edges
	} else {
		return nil
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
	edges := 0
	for _, e := range g.Edges {
		edges += len(e)
	}

	fmt.Printf("%v functions; %v edges\n", len(g.Functions), edges)
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
