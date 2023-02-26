package parsing

import (
	"log"
	"metaphrase/graphs"
	"metaphrase/parsing/c"
	"metaphrase/parsing/golang"
	"os"
	"path/filepath"
	"strings"
)

var SUPPORTED_FILETYPES = map[string]func(rootPath string, verbose int) (graphs.FileGraph, graphs.FunctionGraph){
	"c":  c.BuildGraphs,
	"go": golang.BuildGraphs,
}

func BuildGraph(rootPath string, verbose int, language string) graphs.FunctionGraph {
	// determine language of repository
	var buildFunction func(rootPath string, verbose int) (graphs.FileGraph, graphs.FunctionGraph) = nil

	if len(language) == 0 {
		err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				split := strings.Split(info.Name(), ".")
				filetype := split[len(split)-1]

				if f, ok := SUPPORTED_FILETYPES[filetype]; ok {
					buildFunction = f
					return nil
				}
			}

			return err
		})

		if err != nil {
			log.Fatal(err)
		}
	} else {
		if f, ok := SUPPORTED_FILETYPES[language]; ok {
			buildFunction = f
		} else {
			log.Fatal("parsing.BuildGraph: language " + language + " not supported")
		}
	}

	_, functionGraph := buildFunction(rootPath, verbose)

	return functionGraph
}
