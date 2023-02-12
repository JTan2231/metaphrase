package c

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"metaphrase/graphs"
	"metaphrase/util"
)

func ParseFile(filename string) {
	file, err := os.ReadFile(filename)
	util.CheckError(err)

	println(string(file))
}

func makeRegex(pattern string) *regexp.Regexp {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		log.Fatal(err)
	}

	return regex
}

func getSources(rootPath string) ([]string, []string) {
	headerRegex := makeRegex(".*\\.h$")
	sourceRegex := makeRegex(".*\\.c$")

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

func getLines(filepath string) []string {
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

// get #include filenames from the given lines of a file
// TODO: this prob needs to be more complex/comprehensive
func getImports(lines []string) []string {
	imports := make([]string, 0)

	for _, line := range lines {
		if len(line) > 8 && line[:8] == "#include" {
			name_start := max(strings.Index(line, "\""), strings.Index(line, "<")) + 1
			name_end := max(strings.LastIndex(line, "\""), strings.Index(line, ">"))

			if name_start > 0 && name_end > 0 {
				imports = append(imports, line[name_start:name_end])
			}
		}
	}

	return imports
}

func filenameFromPath(filepath string) string {
	split := strings.Split(filepath, "/")
	return split[len(split)-1]
}

// build FileGraph with this individual file
func processFile(fileGraph *graphs.FileGraph, filepath string) {
	filename := filenameFromPath(filepath)
	fileGraph.AddNode(filename)
	lines := getLines(filepath)
	imports := getImports(lines)

	for _, imp := range imports {
		fileGraph.AddNode(imp)
		fileGraph.AddEdge(filename, imp)
	}
}

// build FileGraph with this directory
func BuildFileGraph(rootPath string) graphs.FileGraph {
	headers, sources := getSources(rootPath)

	fileGraph := graphs.NewFileGraph()

	for _, header := range headers {
		processFile(&fileGraph, header)
	}

	for _, source := range sources {
		processFile(&fileGraph, source)
	}

	fileGraph.PrintEdges()

	return fileGraph
}
