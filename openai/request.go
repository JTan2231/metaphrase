package openai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"metaphrase/graphs"
	"net/http"
)

const authToken = ""

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

func CreateRequest(method string, request completionRequest) (*http.Response, error) {
	reqBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	// TODO: setup to reuse client instead of recreating it every call
	client := http.Client{}

	req, err := http.NewRequest(method, "https://api.openai.com/v1/completions", bytes.NewBuffer(reqBytes))
	req.Header.Set("Accept", "application/json; charset=utf-8")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	return client.Do(req)
}

func CompletionAPICall(function string, fg *graphs.FunctionGraph) string {
	edges := fg.GetEdges(function)
	prompt := ""

	for i, edge := range edges {
		prompt += "// "
	}

	return ""
}
