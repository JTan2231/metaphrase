package main

import (
	"flag"
	"log"
	"metaphrase/graphs"
	"metaphrase/openai"
	"metaphrase/parsing"
	"metaphrase/util/shorthand"
	"os"
	"strings"
)

func main() {
	repoPath := flag.String("repo", "", "path to target repository directory")
	graphPath := flag.String("fg", "", "path to target function graph file")
	language := flag.String("l", "", "target programming language")
	savePath := flag.String("s", "", "serialization target path")

	contextFunction := flag.String("context", "", "function to get context on how it's used in others in the target repository")

	verbose := flag.Int("v", 0, "0 - no output\n1 - file-level\n2 - function-level\n3 - all log messages")
	logFile := flag.String("vo", "", "log file for verbose output")
	regenerate := flag.Bool("r", false, "trigger OpenAI API call and overwrite locally stored context")

	flag.Parse()

	if len(*repoPath) > 0 && len(*graphPath) > 0 {
		log.Fatal("define only one flag: repo or fg")
	}

	if len(*graphPath) > 0 && len(*savePath) > 0 {
		log.Fatal("define only one flag: fg or s")
	}

	if len(*logFile) > 0 {
		file, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal(err)
		}

		defer file.Close()

		log.SetOutput(file)
	}

	var f graphs.FunctionGraph

	if len(*repoPath) > 0 {
		f = parsing.BuildGraph(*repoPath, *verbose, *language)
		f.PrintCounts()

		var filename string
		if len(*savePath) > 0 {
			filename = *savePath
		} else {
			split := strings.Split(*repoPath, "/")
			filtered := make([]string, 0)
			for _, s := range split {
				if len(s) > 0 {
					filtered = append(filtered, s)
				}
			}

			filename = filtered[len(filtered)-1] + ".graph"
		}

		f.Filename = filename
		f.Serialize(f.Filename)
	} else if len(*graphPath) > 0 {
		f.Deserialize(*graphPath)
		f.PrintCounts()
	} else {
		log.Println("no repo/graph file provided; searching for .graph file")

		files, err := os.ReadDir("./")
		if err != nil {
			log.Fatal(err)
		}

		var fileFound bool
		for _, file := range files {
			filename := file.Name()
			if filename[shorthand.Max(len(filename)-6, 0):] == ".graph" {
				f.Deserialize(filename)
				fileFound = true
				break
			}
		}

		if !fileFound {
			log.Fatal("error: target repo, graph file, or graph file in this directory required")
		}

		f.PrintCounts()
	}

	if len(*contextFunction) > 0 {
		openai.GetFunctionContext(*contextFunction, &f, false, *regenerate)
	}
}
