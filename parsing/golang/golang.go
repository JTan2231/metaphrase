package golang

import (
	"bufio"
	"log"
	"metaphrase/graphs"
	"metaphrase/util/shorthand"
	brace "metaphrase/util/stack"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

func getSources(rootPath string) []string {
	sourceRegex := shorthand.MakeRegex(".*\\.go$")

	sources := make([]string, 0)
	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			if sourceRegex.MatchString(info.Name()) {
				sources = append(sources, path)
			}
		}

		return err
	})

	if err != nil {
		log.Fatal(err)
	}

	return sources
}

// TODO: this exact function is also in c.go; move these to a separate common package
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

func filenameFromPath(filepath string) string {
	split := strings.Split(filepath, "/")
	return split[len(split)-1]
}

// TODO: duplicate function. consolidate to separate package
func max(a int, b int) int {
	if a > b {
		return a
	}

	return b
}

func nameFromSignature(signature string) string {
	end := 0

	for end < len(signature) && signature[end] != '(' {
		end++
	}

	return signature[:end]
}

// find all functions in the file, register them in the function graph
//
// parse through file, register all function definitions
// queue function calls within definitions
// process queue by linking existing definitions through function calls within each other
func processFile(fileGraph *graphs.FileGraph, functionGraph *graphs.FunctionGraph, filepath string, verbose int) {
	filename := filenameFromPath(filepath)
	fileGraph.AddNode(filename)
	lines := getLines(filepath)

	l := 0
	//functions := make([]graphs.Function, 0)
	packageName := ""

	words := ""

	// find package name
	for l < len(lines) {
		for i, c := range lines[l] {
			words += string(c)
			n := len(words)
			m := max(n-2, 0)

			// ignore comments
			if strings.Contains(words[m:], "/*") {
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
				break
			}

			if len(packageName) == 0 && words == "package" {
				packageName = strings.Split(lines[l], " ")[1]
				l++
				words = ""
				continue
			}

			// found a function definition
			// begin processing the function
			m = max(len(words)-5, 0)
			if words[m:] == "func " {
				words = ""

				i++

				// if this is a struct.function, back out
				// this shouldn't be registered for context annotations
				//
				// TODO: could be used for something else?
				if lines[l][i] == '(' {
					continue
				}

				for i < len(lines[l]) {
					words += string(lines[l][i])
					i++
				}

				if words[len(words)-1] != '{' {
					log.Fatal("golang.processFile: invalid function definition? " + words)
				}

				signature := words[:len(words)-2]
				name := nameFromSignature(signature)

				function := graphs.Function{
					Filename:  filename,
					Signature: signature,
					Name:      name,
				}

				// begin processing definition
				definition := []string{lines[l]}
				l++
				j := 0
				bs := brace.New('{', '}')
				bs.EvalPush('{')

				// TODO: handle cases where braces are in strings
				for bs.Len() > 0 && l < len(lines) {
					for bs.Len() > 0 && j < len(lines[l]) {
						if lines[l][j] == '\'' {
							j += 2
						} else if lines[l][j] == '(' {
							// probable function call
							start := j - 1
							for lines[l][start] == '.' || unicode.IsLetter(rune(lines[l][start])) {
								start--
							}

							start++
							log.Println("found call: " + lines[l][start:j])
							j++
						} else {
							bs.EvalPush(rune(lines[l][j]))
							j++
						}
					}

					definition = append(definition, lines[l])
					l++
					j = 0
				}

				function.Definition = definition

				break
			}
		}

		l++
	}
}

// build FileGraph with this directory
func BuildGraphs(rootPath string, verbose int) (graphs.FileGraph, graphs.FunctionGraph) {
	sources := getSources(rootPath)

	fileGraph := graphs.NewFileGraph()
	functionGraph := graphs.NewFunctionGraph()

	for _, source := range sources {
		if verbose > 0 {
			log.Println("processing file: " + source)
		}

		processFile(&fileGraph, &functionGraph, source, verbose)
	}

	functionGraph.SetEdges()

	return fileGraph, functionGraph
}
