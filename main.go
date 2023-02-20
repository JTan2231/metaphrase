package main

import (
	"flag"
	"log"
	"metaphrase/graphs"
	"metaphrase/openai"
	"metaphrase/parsing/c"
	"metaphrase/parsing/golang"
	"os"
)

const DEBUG = true

func main() {
	if DEBUG {
		golang.BuildGraphs("/home/joey/go/metaphrase/parsing/c/c.go", 1)
	} else {
		args := os.Args[1:]
		if len(args) == 0 {
			log.Fatal("usage: <todo -- list of flags/args>")
		}

		repoPath := flag.String("repo", "", "path to target repository directory")
		graphPath := flag.String("fg", "", "path to target function graph file")
		language := flag.String("l", "c", "target programming language")
		savePath := flag.String("s", "", "serialization target path")

		contextFunction := flag.String("context", "", "function to get context on how it's used in others in the target repository")

		verbose := flag.Int("v", 0, "0 - no output\n1 - file-level\n2 - function-level\n3 - all log messages")
		logFile := flag.String("vo", "", "log file for verbose output")

		flag.Parse()

		if len(*repoPath) == 0 && len(*graphPath) == 0 {
			log.Fatal("repo xor input graph file required")
		}

		if len(*repoPath) > 0 && len(*graphPath) > 0 {
			log.Fatal("define only one flag: repo or fg")
		}

		if len(*graphPath) > 0 && len(*savePath) > 0 {
			log.Fatal("define only one flag: fg or s")
		}

		if *language != "c" {
			log.Fatal("C is currently the only supported programming language")
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
			_, f = c.BuildGraphs(*repoPath, *verbose)

			f.PrintCounts()

			if len(*savePath) > 0 {
				f.Serialize(*savePath)
				log.Println("function graph saved to " + *savePath)
			}
		} else if len(*graphPath) > 0 {
			f.Deserialize(*graphPath)

			log.Println("function graph loaded from " + *graphPath)
			f.PrintCounts()
		}

		if len(*contextFunction) > 0 {
			response := openai.CompletionAPICall(*contextFunction, &f, false)
			log.Println(" - GPT Response: " + response)
		}
	}
}
