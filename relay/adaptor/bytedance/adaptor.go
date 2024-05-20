package bytedance

import (
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/songquanpeng/one-api/relay/adaptor"
	"github.com/songquanpeng/one-api/relay/meta"
	"github.com/songquanpeng/one-api/relay/model"
	"github.com/songquanpeng/one-api/relay/relaymode"
	"io"
	"net/http"
	"strings"
)

type Adaptor struct {
}

func (a *Adaptor) Init(meta *meta.Meta) {

}

func (a *Adaptor) GetRequestURL(meta *meta.Meta) (string, error) {
	// https://www.volcengine.com/docs/82379/1263594#chat
	url := "https://maas-api.ml-platform-cn-beijing.volces.com/api/v1/chat"

	return url, nil
}

func (a *Adaptor) SetupRequestHeader(c *gin.Context, req *http.Request, meta *meta.Meta) error {
	adaptor.SetupCommonRequestHeader(c, req, meta)
	keys := strings.Split(meta.APIKey, "/")
	if len(keys) != 2 {
		return errors.New("invalid api key")
	}
	ak := keys[0]
	sk := keys[1]

	reqBody := c.GetString("requestBody")
	headerSign, _ := buildRequestHeaders(ak, sk, reqBody)
	for key, value := range headerSign {
		req.Header.Set(key, value)
	}

	return nil
}

func (a *Adaptor) ConvertRequest(c *gin.Context, relayMode int, request *model.GeneralOpenAIRequest) (any, error) {
	if request == nil {
		return nil, errors.New("request is nil")
	}
	switch relayMode {
	case relaymode.Embeddings:
		bytedanceEmbeddingRequest := ConvertEmbeddingRequest(*request)
		marshal, _ := json.Marshal(bytedanceEmbeddingRequest)
		c.Set("requestBody", string(marshal))
		return bytedanceEmbeddingRequest, nil
	default:
		bytedanceRequest := ConvertRequest(*request)
		// 转换为json字符串
		marshal, _ := json.Marshal(bytedanceRequest)
		c.Set("requestBody", string(marshal))
		return bytedanceRequest, nil
	}
}

func (a *Adaptor) ConvertImageRequest(request *model.ImageRequest) (any, error) {
	if request == nil {
		return nil, errors.New("request is nil")
	}
	return request, nil
}

func (a *Adaptor) DoRequest(c *gin.Context, meta *meta.Meta, requestBody io.Reader) (*http.Response, error) {
	return adaptor.DoRequestHelper(a, c, meta, requestBody)
}

func (a *Adaptor) DoResponse(c *gin.Context, resp *http.Response, meta *meta.Meta) (usage *model.Usage, err *model.ErrorWithStatusCode) {
	if meta.IsStream {
		err, usage = StreamHandler(c, resp)
	} else {
		switch meta.Mode {
		case relaymode.Embeddings:
			err, usage = EmbeddingHandler(c, resp)
		default:
			err, usage = Handler(c, resp)
		}
	}
	return
}

func (a *Adaptor) GetModelList() []string {
	return ModelList
}

func (a *Adaptor) GetChannelName() string {
	return "bytedance"
}
