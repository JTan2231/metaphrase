package main

import (
	"fmt"
	"metaphrase/openai"
	"metaphrase/parsing/c"
)

func main() {
	_, f := c.BuildGraphs("/home/joey/c/ffmpeg/")

	response := openai.CompletionAPICall("dss_skip_audio_header", &f, false)
	fmt.Println("RESPONSE: " + response)
}
