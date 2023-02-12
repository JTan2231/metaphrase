package graphs

import (
	"errors"
	"fmt"
)

// neighbors are outgoing edges
type fileNode struct {
	Filename string
}

// directed graph
// Edges refers to outgoing edges for a node_id
type FileGraph struct {
	Nodes map[string]*fileNode
	Edges map[string][]*fileNode
}

func NewFileGraph() FileGraph {
	return FileGraph{
		Nodes: make(map[string]*fileNode),
		Edges: make(map[string][]*fileNode),
	}
}

func (g FileGraph) getNode(filename string) *fileNode {
	if node, ok := g.Nodes[filename]; ok {
		return node
	} else {
		return nil
	}
}

func (g FileGraph) AddNode(filename string) error {
	if g.getNode(filename) != nil {
		return errors.New(fmt.Sprintf("file_graph: node %s already exists", filename))
	}

	g.Nodes[filename] = &fileNode{
		Filename: filename,
	}

	return nil
}

func (g FileGraph) edgeExists(from string, to string) bool {
	if edges, ok := g.Edges[from]; ok {
		for _, node := range edges {
			if node.Filename == to {
				return true
			}
		}
	}

	return false
}

func (g FileGraph) AddEdge(from string, to string) error {
	if g.edgeExists(from, to) {
		return errors.New(fmt.Sprintf("file_graph: edge (%v, %v) already exists", from, to))
	}

	if edges, ok := g.Edges[from]; ok {
		edges = append(edges, g.Nodes[to])
		g.Edges[from] = edges
	} else {
		g.Edges[from] = []*fileNode{g.Nodes[to]}
	}

	return nil
}

func (g FileGraph) PrintEdges() {
	for node, edges := range g.Edges {
		fmt.Printf("node %s has edges:\n", node)
		for _, edge := range edges {
			fmt.Printf("  - %s -> %s\n", node, edge.Filename)
		}

		fmt.Println("")
	}

}
