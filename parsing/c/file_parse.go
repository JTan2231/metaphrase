package c

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"metaphrase/graphs"
	"metaphrase/util/shorthand"
)

func getSources(rootPath string) ([]string, []string) {
	headerRegex := shorthand.MakeRegex(".*\\.h$")
	sourceRegex := shorthand.MakeRegex(".*\\.c$")

	headers := make([]string, 0)
	sources := make([]string, 0)
	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			if headerRegex.MatchString(info.Name()) {
				headers = append(headers, path)
			} else if sourceRegex.MatchString(info.Name()) {
				sources = append(sources, path)
			}
		}

		return err
	})

	if err != nil {
		log.Fatal(err)
	}

	return headers, sources
}

func GetLines(filepath string) []string {
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	lines := make([]string, 0)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return lines
}

func max(a int, b int) int {
	if a > b {
		return a
	}

	return b
}

func findAfterIndex(line string, idx int, term string) int {
	i := idx
	for i < len(line) {
		if strings.Contains(term, string(line[i])) {
			break
		}

		i++
	}

	return i
}

// get #include filenames from the given lines of a file
// TODO: this prob needs to be more complex/comprehensive
func getImports(lines []string) []string {
	imports := make([]string, 0)

	for _, line := range lines {
		if len(line) > 8 && line[:8] == "#include" {
			nameStart := findAfterIndex(line, 8, "<\"")
			nameEnd := findAfterIndex(line, nameStart+1, ">\"")

			if nameStart > 0 && nameEnd > 0 && nameEnd < len(line) {
				imports = append(imports, line[nameStart:nameEnd])
			}
		}
	}

	return imports
}

func stringFromLines(lines []string) string {
	var out string
	for _, line := range lines {
		out += line
	}

	return out
}

func filenameFromPath(filepath string) string {
	split := strings.Split(filepath, "/")
	return split[len(split)-1]
}

// build FileGraph with this individual file
func processFile(fileGraph *graphs.FileGraph, functionGraph *graphs.FunctionGraph, filepath string) {
	filename := filenameFromPath(filepath)
	fileGraph.AddNode(filename)
	lines := GetLines(filepath)
	imports := getImports(lines)

	fileGraph.AddNodeContent(filename, lines)

	functions := make(map[string][]string)

	fs := make([]string, 0)
	l := 0
	for l < len(lines) {
		line := lines[l]
		words := ""
		for _, c := range line {
			words += string(c)
			n := len(words)
			m := max(n-2, 0)
			if strings.Contains(words[m:], "/*") {
				fs = append(fs, words[:m])

				words = words[m:]
				commentEnd := false
				for l < len(lines) && !commentEnd {
					commentEnd = strings.Contains(lines[l], "*/")
					l++
				}

				break
			} else if strings.Contains(words[m:], "//") {
				words = ""
				continue
			}

			if words[n-1] == '(' {
				fmt.Println(words)
				fmt.Println("full line: " + line)
				words = ""

				continue
			}
		}

		l++
	}

	// copy over/filter out undefined function calls from the functions
	for function := range functions {
		for _, call := range functions[function] {
			if _, ok := functionGraph.Functions[call]; ok {
				functionGraph.AddEdge(function, call)
			}
		}
	}

	for _, imp := range imports {
		fileGraph.AddNode(imp)
		fileGraph.AddEdge(filename, imp)
	}
}

// build FileGraph with this directory
func BuildGraphs(rootPath string) (graphs.FileGraph, graphs.FunctionGraph) {
	headers, sources := getSources(rootPath)

	fileGraph := graphs.NewFileGraph()
	functionGraph := graphs.NewFunctionGraph()

	for _, header := range headers {
		processFile(&fileGraph, &functionGraph, header)
	}

	for _, source := range sources {
		processFile(&fileGraph, &functionGraph, source)
	}

	//fileGraph.PrintEdges()

	return fileGraph, functionGraph
}
