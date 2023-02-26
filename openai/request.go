package openai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"metaphrase/graphs"
	"net/http"
	"os"
)

type completionRequest struct {
	Model            string         `json:"model"`
	Prompt           string         `json:"prompt,omitempty"`
	Suffix           string         `json:"suffix,omitempty"`
	MaxTokens        int            `json:"max_tokens,omitempty"`
	Temperature      float32        `json:"temperature,omitempty"`
	TopP             float32        `json:"top_p,omitempty"`
	N                int            `json:"n,omitempty"`
	Stream           bool           `json:"stream,omitempty"`
	LogProbs         int            `json:"logprobs,omitempty"`
	Echo             bool           `json:"echo,omitempty"`
	Stop             []string       `json:"stop,omitempty"`
	PresencePenalty  float32        `json:"presence_penalty,omitempty"`
	FrequencyPenalty float32        `json:"frequency_penalty,omitempty"`
	BestOf           int            `json:"best_of,omitempty"`
	LogitBias        map[string]int `json:"logit_bias,omitempty"`
	User             string         `json:"user,omitempty"`
}

type CompletionChoice struct {
	Text         string `json:"text"`
	Index        int    `json:"index"`
	FinishReason string `json:"finish_reason"`
}

type CompletionResponse struct {
	ID      string             `json:"id"`
	Object  string             `json:"object"`
	Created int64              `json:"created"`
	Model   string             `json:"model"`
	Choices []CompletionChoice `json:"choices"`
}

func MakeRequest(method string, request completionRequest) (*http.Response, error) {
	reqBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	// TODO: setup to reuse client instead of recreating it every call
	client := http.Client{}

	req, err := http.NewRequest(method, "https://api.openai.com/v1/completions", bytes.NewBuffer(reqBytes))
	req.Header.Set("Accept", "application/json; charset=utf-8")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", os.Getenv("OPENAI_API_KEY")))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	return client.Do(req)
}

func GetFunctionContext(function string, fg *graphs.FunctionGraph, showPrompt bool, regenerate bool) {
	var functionNode *graphs.FunctionNode
	if node, ok := fg.Functions[function]; ok {
		functionNode = node
	} else {
		functionNode = nil
	}

	if !regenerate {
		if edge, ok := fg.Imports[function]; ok {
			if len(edge.Context) > 0 {
				log.Println(edge.Context)
				return
			}
		} else {
			log.Fatal("openai.GetFunctionContext: couldn't find import edges for function " + function)
		}
	}

	if functionNode == nil {
		log.Fatal("openai.CompletionAPICall: function " + function + " does not exist in function graph")
	}

	edges := fg.GetImports(function).Functions
	prompt := ""

	if len(edges) == 0 {
		log.Fatal("openai.GetFunctionContext: function " + function + " is not used in any other functions")
	}

	for i, edge := range edges {
		prompt += "// Function " + fmt.Sprint(i+1) + "\n"
		for _, line := range edge.Definition {
			prompt += line + "\n"
		}

		prompt += "\n"
	}

	prompt += fmt.Sprintf("// How is the function `%s` used in the other functions above?", function)

	tokenCount := int(len(prompt) / 4)
	if tokenCount > 2000 {
		log.Fatal("openai.CompletionAPICall: prompt contains too many tokens")
	}

	if showPrompt {
		fmt.Println("---------- PROMPT ----------")
		fmt.Println(prompt)
		fmt.Println("----------------------------")
	}

	response := CompletionAPICall(prompt)
	if edge, ok := fg.Imports[function]; ok {
		edge.Context = response
		fg.Imports[function] = edge
	} else {
		log.Fatal("openai.GetFunctionContext: couldn't find import edges for function " + function)
	}

	log.Println(response)
	fg.Serialize(fg.Filename)
	log.Println("updated function graph saved to " + fg.Filename)
}

func CompletionAPICall(prompt string) string {
	req := completionRequest{
		Model:       "text-davinci-003",
		Prompt:      prompt,
		MaxTokens:   128,
		Temperature: 0.5,
	}

	resp, err := MakeRequest("POST", req)

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	var response CompletionResponse
	err = json.NewDecoder(resp.Body).Decode(&response)

	if resp.StatusCode != 200 {
		log.Fatal("CompletionAPICall: " + resp.Status)
	}

	return response.Choices[0].Text
}
