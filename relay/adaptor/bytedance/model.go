package bytedance

import (
	"github.com/songquanpeng/one-api/relay/model"
)

type ErrorInfo struct {
	Code    int    `json:"code"`
	CodeN   string `json:"code_n"`
	Message string `json:"message"`
}

type ChoiceInfo struct {
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

type ChatResponse struct {
	ReqId  string      `json:"req_id"`
	Choice ChoiceInfo  `json:"choice"`
	Usage  model.Usage `json:"usage"`
	Error  ErrorInfo   `json:"error"`
}

type ChatStreamResponse struct {
	ChatResponse
	SentenceId int  `json:"sentence_id"`
	IsEnd      bool `json:"is_end"`
}

type ModelInfo struct {
	ModelName string `json:"model_name"`
}

type DataInfo struct {
	DataType string `json:"data_type"`
	Text     string `json:"text"`
}

type EmbeddingRequest struct {
	Model ModelInfo  `json:"model"`
	Data  []DataInfo `json:"data"`
}

type EmbeddingData struct {
	Object    string    `json:"object"`
	Embedding []float64 `json:"embedding"`
	Index     int       `json:"index"`
}

type EmbeddingResponse struct {
	Id      string          `json:"id"`
	Object  string          `json:"object"`
	Created int64           `json:"created"`
	Data    []EmbeddingData `json:"data"`
	Usage   model.Usage     `json:"usage"`
	Error
}
