package c

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"metaphrase/graphs"
	"metaphrase/util/shorthand"
	brace "metaphrase/util/stack"
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

func min(a int, b int) int {
	if a < b {
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

func getFunctionName(line string) string {
	end := 0
	for end < len(line) {
		if line[end] == '(' {
			break
		}

		end++
	}

	start := end - 1
	for start > 0 {
		if !(unicode.IsLetter(rune(line[start])) || line[start] == '_') {
			break
		}

		start--
	}

	return strings.TrimSpace(line[start:end])
}

// build FileGraph with this individual file
func processFile(fileGraph *graphs.FileGraph, functionGraph *graphs.FunctionGraph, filepath string) {
	filename := filenameFromPath(filepath)
	fileGraph.AddNode(filename)
	lines := GetLines(filepath)
	imports := getImports(lines)

	fileGraph.AddNodeContent(filename, lines)

	functions := make([]graphs.Function, 0)

	// this can probably be cleaned up
	typeNames := regexp.MustCompile("void |unsigned |char |int |uint |long |float |double |static ")
	branchingNames := regexp.MustCompile("if|while|for")
	fs := make([]string, 0)
	l := 0
	for l < len(lines) {
		line := lines[l]
		if len(line) > 0 && line[0] == '#' {
			skip := 1
			tl := l
			for tl < len(lines) && len(lines[tl]) > 0 && string(lines[tl][len(lines[tl])-1]) == `\` {
				skip++
				tl++
			}

			l += skip

			continue
		}

		words := ""
		for i, c := range line {
			words += string(c)
			n := len(words)
			m := max(n-2, 0)

			// ignore comments
			if strings.Contains(words[m:], "/*") {
				fs = append(fs, words[:m])

				words = words[m:]
				commentEnd := false
				for l < len(lines) && !commentEnd {
					commentEnd = strings.Contains(lines[l], "*/")
					l++
				}

				if commentEnd {
					l--
				}

				break
			} else if strings.Contains(words[m:], "//") {
				words = ""
				continue
			}

			// potential function call/definition
			if words[n-1] == '(' {
				// ignore #define macros
				if lines[l][0] == '#' {
					continue
				}

				if n > 1 && unicode.IsLetter(rune(words[n-2])) {
					// get the entire function signature/call with arguments
					bs := brace.New('(', ')')
					bs.EvalPush(rune(words[n-1]))

					wordsParentheseIndex := len(words) - 1

					idx := i + 1
					cl := l
					for cl < len(lines) && bs.Len() > 0 {
						for bs.Len() > 0 && idx < len(lines[cl]) {
							nc := string(lines[cl][idx])
							words += nc

							bs.EvalPush(rune(lines[cl][idx]))

							idx++
						}

						if bs.Len() == 0 {
							break
						} else {
							cl++
							idx = 0
						}
					}

					// cut off everything else in the line
					idx = wordsParentheseIndex - 1
					rwi := rune(words[idx])
					for idx > 0 && (unicode.IsLetter(rwi) || rwi == '_' || rwi == ' ') {
						idx--
						rwi = rune(words[idx])
					}

					if !unicode.IsLetter(rune(words[idx])) {
						idx++
					}

					words = words[idx:]
					words = strings.TrimSpace(words)

					isDefinition := false
					isDeclaration := false
					def := make([]string, 0)
					// is it a function declaration/definition?
					if typeNames.MatchString(words[:strings.Index(words, "(")]) {
						// find the defition
						cl = l
						for cl < len(lines) {
							// find the starting brace
							for j, dc := range lines[cl] {
								if dc == '{' {
									// log the definition
									isDefinition = true
									dbs := brace.New('{', '}')
									dbs.EvalPush(dc)

									idx := j + 1
									for cl < len(lines) && dbs.Len() > 0 {
										def = append(def, lines[cl])
										for dbs.Len() > 0 && idx < len(lines[cl]) {
											dbs.EvalPush(rune(lines[cl][idx]))
											idx++
										}

										cl++
										idx = 0
									}

									break
								} else if dc == ';' {
									isDeclaration = true
								}
							}

							if len(def) > 0 || isDeclaration {
								break
							}

							cl++
						}
					}

					// remove the `return` keyword if it's there
					if len(words) > 6 && words[:7] == "return " {
						words = words[7:]
					}

					name := getFunctionName(words)
					if branchingNames.MatchString(name) {
						continue
					}

					if isDefinition {
						signature := words

						functions = append(functions, graphs.Function{
							Filename:   filename,
							Signature:  signature,
							Name:       name,
							Definition: def,
							Calls:      make(map[string]bool, 0),
						})
					} else {
						// this is to throw away function declarations
						// functions are logged in the graph only if they're defined
						if len(functions) > 0 {
							functions[len(functions)-1].Calls[name] = true
						}
					}

					words = ""
				}

				continue
			}
		}

		l++
	}

	// add the functions to the graph
	for _, f := range functions {
		functionGraph.AddFunction(f)
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
