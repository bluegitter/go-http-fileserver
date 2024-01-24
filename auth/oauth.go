package auth

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"server/config"
	"server/logging"
	"strconv"
)

func RequestAccessToken(code string, config config.Config) (string, error) {
	// 构建请求
	req, err := http.NewRequest("POST", config.OAuthTokenURL, nil)
	if err != nil {
		return "", err
	}

	query := req.URL.Query()
	query.Add("client_id", "sso")
	query.Add("client_secret", "sso-secret")
	query.Add("grant_type", "authorization_code")
	query.Add("redirect_uri", "http://"+config.BindIP+":"+strconv.Itoa(config.Port)+"/callback")
	query.Add("code", code)
	req.URL.RawQuery = query.Encode()

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// 解析响应以获取 Access Token
	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	jsonResult, err := json.Marshal(result)
	if err != nil {
		// 处理错误
		return "", err
	}

	logging.ConsoleLogger.Printf("access_token: "+logging.ColorGreen+"%s"+logging.ColorReset, string(jsonResult))
	return result.AccessToken, nil
}

func ValidateToken(token string, config config.Config) bool {
	req, err := http.NewRequest("POST", config.OAuthCheckTokenURL, nil)
	if err != nil {
		return false
	}

	query := req.URL.Query()
	query.Add("token", token)
	req.URL.RawQuery = query.Encode()

	// 对 client_id:client_secret 进行 Base64 编码
	auth := config.ClientID + ":" + config.ClientSecret
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))

	// 设置 HTTP Authorization Header
	req.Header.Add("Authorization", "Basic "+encodedAuth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body) // 读取响应体
	if err != nil {
		log.Fatal(err) // 或者用其他方式处理错误
	}

	logging.ConsoleLogger.Printf("check_token: "+logging.ColorGreen+"%s"+logging.ColorReset, string(body))

	if resp.StatusCode != http.StatusOK {
		return false
	}
	return true
}
