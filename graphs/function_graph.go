package graphs

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"log"
	"os"
	"strings"
)

type Function struct {
	Filename   string
	Signature  string
	Name       string
	Definition []string
	Calls      map[string]bool
}

type FunctionNode struct {
	Filename        string
	Signature       string
	Name            string
	Definition      []string
	DefinitionLine  int
	DeclarationLine int
}

type FunctionGraph struct {
	Functions          map[string]*FunctionNode
	Dependencies       map[string][]*FunctionNode
	Imports            map[string][]*FunctionNode
	dependencyQueueSet map[string][]string // probably needs a better name
}

func NewFunctionGraph() FunctionGraph {
	return FunctionGraph{
		Functions:          make(map[string]*FunctionNode),
		Dependencies:       make(map[string][]*FunctionNode),
		Imports:            make(map[string][]*FunctionNode),
		dependencyQueueSet: make(map[string][]string),
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
func (g *FunctionGraph) AddFunction(f Function) {
	if _, ok := g.Functions[f.Name]; !ok {
		g.Functions[f.Name] = &FunctionNode{
			Name:       f.Name,
			Filename:   f.Filename,
			Signature:  f.Signature,
			Definition: f.Definition,
		}

		calls := make([]string, 0)
		for call := range f.Calls {
			calls = append(calls, call)
		}

		g.dependencyQueueSet[f.Name] = calls
	}
}

func (g *FunctionGraph) getFunctionNode(name string) *FunctionNode {
	if node, ok := g.Functions[name]; ok {
		return node
	} else {
		return nil
	}
}

// clears g.dependencyQueueSet
func (g *FunctionGraph) SetEdges() {
	undefinedFunctions := make(map[string]bool, 0)
	for caller, callees := range g.dependencyQueueSet {
		callerNode := g.getFunctionNode(caller)
		if callerNode == nil {
			log.Fatal("SetEdges: callerNode function " + caller + " does not exist in function graph")
		}

		for _, callee := range callees {
			calleeNode := g.getFunctionNode(callee)
			if calleeNode == nil {
				undefinedFunctions[callee] = true
				continue
			}

			if edges, ok := g.Dependencies[caller]; ok {
				edges = append(edges, calleeNode)
				g.Dependencies[caller] = edges
			} else {
				g.Dependencies[caller] = []*FunctionNode{calleeNode}
			}

			if edges, ok := g.Imports[callee]; ok {
				edges = append(edges, callerNode)
				g.Imports[callee] = edges
			} else {
				g.Imports[callee] = []*FunctionNode{callerNode}
			}
		}
	}
}

func (g *FunctionGraph) GetDependencies(from string) []*FunctionNode {
	if edges, ok := g.Dependencies[from]; ok {
		return edges
	} else {
		return nil
	}
}

func (g *FunctionGraph) GetImports(from string) []*FunctionNode {
	if edges, ok := g.Imports[from]; ok {
		return edges
	} else {
		return nil
	}
}

func (g *FunctionGraph) PrintNodes(verbose bool) {
	for filename, node := range g.Functions {
		log.Println("function name: " + filename)

		if verbose {
			for lineNumber, line := range node.Definition {
				log.Println(fmt.Sprint(lineNumber) + ": " + line)
			}
		}
	}

	log.Printf("printed %v functions\n", len(g.Functions))
}

func (g *FunctionGraph) PrintEdges() {
	for from := range g.Dependencies {
		node := g.Functions[from]
		for _, to := range g.Dependencies[from] {
			log.Printf("%s -> %s\n", node.Name, to.Name)
		}

		log.Println("------------")
	}
}

func (g *FunctionGraph) PrintImportEdges() {
	for from := range g.Imports {
		node := g.Functions[from]
		for _, to := range g.Imports[from] {
			log.Printf("%s -> %s\n", node.Name, to.Name)
		}

		log.Println("------------")
	}
}

func (g *FunctionGraph) PrintImportEdge(name string) {
	log.Println("Import edges for " + name + ":")
	if edges, ok := g.Imports[name]; ok {
		for _, to := range edges {
			log.Printf("  - %s -> %s\n", name, to.Name)
		}
	}
}

func (g *FunctionGraph) PrintCounts() {
	edges := 0
	for _, e := range g.Dependencies {
		edges += len(e)
	}

	log.Printf("%v functions; %v edges\n", len(g.Functions), edges)
}

func (g *FunctionGraph) PrintNode(function string) {
	log.Println("printing function " + function)
	if node, ok := g.Functions[function]; ok {
		for _, to := range g.Dependencies[function] {
			log.Printf("%s -> %s\n", node.Name, to.Name)
		}
	} else {
		log.Println("error: couldn't find " + function)
	}

	log.Println("------------")
}

func (g *FunctionGraph) Serialize(filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}

	writer := bufio.NewWriter(file)
	encoder := gob.NewEncoder(writer)

	if err := encoder.Encode(g); err != nil {
		log.Fatal(err)
	}
}

func (g *FunctionGraph) Deserialize(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&g); err != nil {
		log.Fatal(err)
	}
}
