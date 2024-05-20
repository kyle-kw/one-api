package bytedance

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/songquanpeng/one-api/common"
	"github.com/songquanpeng/one-api/common/logger"
	"github.com/songquanpeng/one-api/relay/adaptor/openai"
	"github.com/songquanpeng/one-api/relay/constant"
	"github.com/songquanpeng/one-api/relay/model"
	"io"
	"net/http"
	"strings"
	"time"
)

// https://www.volcengine.com/docs/82379/1263594#chat

type TokenResponse struct {
	ExpiresIn   int    `json:"expires_in"`
	AccessToken string `json:"access_token"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatRequestParameters struct {
	MaxNewTokens    int     `json:"max_new_tokens,omitempty"`
	MinNewTokens    int     `json:"min_new_tokens,omitempty"`
	Temperature     float64 `json:"temperature,omitempty"`
	TopP            float64 `json:"top_p,omitempty,omitempty"`
	Topk            int     `json:"top_k,omitempty,omitempty"`
	MaxPromptTokens int     `json:"max_prompt_tokens,omitempty"`
}

type Model struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	EndpointId string `json:"endpoint_id,omitempty"`
}

type ChatRequest struct {
	Model      Model                 `json:"model"`
	Parameters ChatRequestParameters `json:"parameters,omitempty"`
	Messages   []Message             `json:"messages"`
	Stream     bool                  `json:"stream,omitempty"`
}

type Error struct {
	ErrorCode int    `json:"error_code"`
	ErrorMsg  string `json:"error_msg"`
}

// hmacSHA256 非对称加密
func hmacSHA256(key []byte, content string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(content))
	return h.Sum(nil)
}

// hashSHA256 hash算法
func hashSHA256(content string) string {
	h := sha256.New()
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

type Credential struct {
	AccessKeyID     string
	SecretAccessKey string
	Service         string
	Region          string
}

type RequestParam struct {
	Body        string
	Host        string
	Path        string
	Method      string
	ContentType string
	Date        time.Time
}

func buildRequestHeaders(ak, sk string, body string) (map[string]string, error) {
	// 创建身份证明
	credential := Credential{
		AccessKeyID:     ak,
		SecretAccessKey: sk,
		Service:         "ml_maas",
		Region:          "cn-beijing",
	}

	// 初始化签名结构体
	requestParam := RequestParam{
		Body:        body,
		Host:        "maas-api.ml-platform-cn-beijing.volces.com",
		Path:        "/api/v1/chat",
		Method:      "POST",
		ContentType: "application/json",
		Date:        time.Now().UTC(),
	}

	xDate := requestParam.Date.Format("20060102T150405Z")
	shortXDate := xDate[:8]
	xContentSHA256 := hashSHA256(requestParam.Body)

	// 初始化签名结果的结构体
	signResult := map[string]string{
		"Accept":           "application/json",
		"Host":             requestParam.Host,
		"X-Content-Sha256": xContentSHA256,
		"X-Date":           xDate,
		"Content-Type":     requestParam.ContentType,
	}

	// 计算 Signature 签名
	signedHeadersStr := "content-type;host;x-content-sha256;x-date"

	canonicalRequestStr := strings.Join([]string{
		requestParam.Method,
		requestParam.Path,
		"", // query
		strings.Join([]string{
			"content-type:" + requestParam.ContentType,
			"host:" + requestParam.Host,
			"x-content-sha256:" + xContentSHA256,
			"x-date:" + xDate,
		}, "\n"),
		"",
		signedHeadersStr,
		xContentSHA256,
	}, "\n")

	hashedCanonicalRequest := hashSHA256(canonicalRequestStr)

	credentialScope := strings.Join([]string{shortXDate, credential.Region, credential.Service, "request"}, "/")
	stringToSign := strings.Join([]string{"HMAC-SHA256", xDate, credentialScope, hashedCanonicalRequest}, "\n")

	kDate := hmacSHA256([]byte(credential.SecretAccessKey), shortXDate)
	kRegion := hmacSHA256(kDate, credential.Region)
	kService := hmacSHA256(kRegion, credential.Service)
	kSigning := hmacSHA256(kService, "request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	signResult["Authorization"] = fmt.Sprintf(
		"HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		credential.AccessKeyID, credentialScope, signedHeadersStr, signature,
	)

	fmt.Println(signResult["Authorization"])

	return signResult, nil
}

func ConvertRequest(request model.GeneralOpenAIRequest) *ChatRequest {
	bytedanceRequest := ChatRequest{
		Messages: make([]Message, 0, len(request.Messages)),
		Parameters: ChatRequestParameters{
			MaxNewTokens: request.MaxTokens,
			Temperature:  request.Temperature,
			TopP:         request.TopP,
		},
		Model:  Model{Name: request.Model},
		Stream: request.Stream,
	}
	for _, message := range request.Messages {
		bytedanceRequest.Messages = append(bytedanceRequest.Messages, Message{
			Role:    message.Role,
			Content: message.StringContent(),
		})
	}

	return &bytedanceRequest
}

func responseBaidu2OpenAI(response *ChatResponse) *openai.TextResponse {
	choice := openai.TextResponseChoice{
		Index: 0,
		Message: model.Message{
			Role:    "assistant",
			Content: response.Choice.Message.Content,
		},
		FinishReason: "stop",
	}
	fullTextResponse := openai.TextResponse{
		Id:      response.ReqId,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Choices: []openai.TextResponseChoice{choice},
		Usage:   response.Usage,
	}
	return &fullTextResponse
}

func streamResponseBaidu2OpenAI(baiduResponse *ChatStreamResponse) *openai.ChatCompletionsStreamResponse {
	var choice openai.ChatCompletionsStreamResponseChoice
	choice.Delta.Content = baiduResponse.Choice.Message.Content
	if baiduResponse.Choice.FinishReason == "stop" {
		choice.FinishReason = &constant.StopFinishReason
	}
	response := openai.ChatCompletionsStreamResponse{
		Id:      baiduResponse.ReqId,
		Object:  "chat.completion.chunk",
		Created: time.Now().Unix(),
		Model:   "",
		Choices: []openai.ChatCompletionsStreamResponseChoice{choice},
	}
	return &response
}

func ConvertEmbeddingRequest(request model.GeneralOpenAIRequest) *EmbeddingRequest {
	inputs := request.ParseInput()
	nums := make([]DataInfo, 0, len(inputs))

	// 使用 for 循环来填充切片
	for _, input := range inputs {
		nums = append(nums, DataInfo{
			DataType: "text",
			Text:     input,
		})
	}

	return &EmbeddingRequest{
		Model: ModelInfo{
			ModelName: request.Model,
		},
		Data: nums,
	}
}

func embeddingResponseBaidu2OpenAI(response *EmbeddingResponse) *openai.EmbeddingResponse {
	openAIEmbeddingResponse := openai.EmbeddingResponse{
		Object: "list",
		Data:   make([]openai.EmbeddingResponseItem, 0, len(response.Data)),
		Model:  "baidu-embedding",
		Usage:  response.Usage,
	}
	for _, item := range response.Data {
		openAIEmbeddingResponse.Data = append(openAIEmbeddingResponse.Data, openai.EmbeddingResponseItem{
			Object:    item.Object,
			Index:     item.Index,
			Embedding: item.Embedding,
		})
	}
	return &openAIEmbeddingResponse
}

func StreamHandler(c *gin.Context, resp *http.Response) (*model.ErrorWithStatusCode, *model.Usage) {
	var usage model.Usage
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := strings.Index(string(data), "\n"); i >= 0 {
			return i + 1, data[0:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	dataChan := make(chan string)
	stopChan := make(chan bool)
	go func() {
		for scanner.Scan() {
			data := scanner.Text()
			if len(data) < 6 { // ignore blank line or wrong format
				continue
			}
			data = data[5:]
			dataChan <- data
		}
		stopChan <- true
	}()
	common.SetEventStreamHeaders(c)
	c.Stream(func(w io.Writer) bool {
		select {
		case data := <-dataChan:
			var bytedanceResponse ChatStreamResponse
			err := json.Unmarshal([]byte(data), &bytedanceResponse)
			if err != nil {
				logger.SysError("error unmarshalling stream response: " + err.Error())
				return true
			}
			if bytedanceResponse.Usage.TotalTokens != 0 {
				usage.TotalTokens = bytedanceResponse.Usage.TotalTokens
				usage.PromptTokens = bytedanceResponse.Usage.PromptTokens
				usage.CompletionTokens = bytedanceResponse.Usage.CompletionTokens
			}
			response := streamResponseBaidu2OpenAI(&bytedanceResponse)
			jsonResponse, err := json.Marshal(response)
			if err != nil {
				logger.SysError("error marshalling stream response: " + err.Error())
				return true
			}
			c.Render(-1, common.CustomEvent{Data: "data: " + string(jsonResponse)})
			return true
		case <-stopChan:
			c.Render(-1, common.CustomEvent{Data: "data: [DONE]"})
			return false
		}
	})
	err := resp.Body.Close()
	if err != nil {
		return openai.ErrorWrapper(err, "close_response_body_failed", http.StatusInternalServerError), nil
	}
	return nil, &usage
}

func Handler(c *gin.Context, resp *http.Response) (*model.ErrorWithStatusCode, *model.Usage) {
	var bytedanceResponse ChatResponse
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return openai.ErrorWrapper(err, "read_response_body_failed", http.StatusInternalServerError), nil
	}
	err = resp.Body.Close()
	if err != nil {
		return openai.ErrorWrapper(err, "close_response_body_failed", http.StatusInternalServerError), nil
	}
	err = json.Unmarshal(responseBody, &bytedanceResponse)
	if err != nil {
		return openai.ErrorWrapper(err, "unmarshal_response_body_failed", http.StatusInternalServerError), nil
	}
	if bytedanceResponse.Error.Message != "" {
		return &model.ErrorWithStatusCode{
			Error: model.Error{
				Message: bytedanceResponse.Error.Message,
				Type:    "bytedance_error",
				Param:   "",
				Code:    bytedanceResponse.Error.Code,
			},
			StatusCode: resp.StatusCode,
		}, nil
	}
	fullTextResponse := responseBaidu2OpenAI(&bytedanceResponse)
	fullTextResponse.Model = "ernie-bot"
	jsonResponse, err := json.Marshal(fullTextResponse)
	if err != nil {
		return openai.ErrorWrapper(err, "marshal_response_body_failed", http.StatusInternalServerError), nil
	}
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(resp.StatusCode)
	_, err = c.Writer.Write(jsonResponse)
	return nil, &fullTextResponse.Usage
}

func EmbeddingHandler(c *gin.Context, resp *http.Response) (*model.ErrorWithStatusCode, *model.Usage) {
	var baiduResponse EmbeddingResponse
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return openai.ErrorWrapper(err, "read_response_body_failed", http.StatusInternalServerError), nil
	}
	err = resp.Body.Close()
	if err != nil {
		return openai.ErrorWrapper(err, "close_response_body_failed", http.StatusInternalServerError), nil
	}
	err = json.Unmarshal(responseBody, &baiduResponse)
	if err != nil {
		return openai.ErrorWrapper(err, "unmarshal_response_body_failed", http.StatusInternalServerError), nil
	}
	if baiduResponse.ErrorMsg != "" {
		return &model.ErrorWithStatusCode{
			Error: model.Error{
				Message: baiduResponse.ErrorMsg,
				Type:    "baidu_error",
				Param:   "",
				Code:    baiduResponse.ErrorCode,
			},
			StatusCode: resp.StatusCode,
		}, nil
	}
	fullTextResponse := embeddingResponseBaidu2OpenAI(&baiduResponse)
	jsonResponse, err := json.Marshal(fullTextResponse)
	if err != nil {
		return openai.ErrorWrapper(err, "marshal_response_body_failed", http.StatusInternalServerError), nil
	}
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(resp.StatusCode)
	_, err = c.Writer.Write(jsonResponse)
	return nil, &fullTextResponse.Usage
}
