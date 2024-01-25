package config

import (
	"log"

	"gopkg.in/ini.v1"
)

type Config struct {
	DataDir            string `ini:"data_dir"`
	BindIP             string `ini:"bind_ip"`
	Port               int    `ini:"port"`
	SecretKey          string `ini:"secret_key"`
	OAuthTokenURL      string `ini:"oauth_token_url"`
	OAuthCheckTokenURL string `ini:"oauth_check_token_url"`
	OAuthAuthorizeURL  string `ini:"oauth_authorize_url"`
	ClientID           string `ini:"client_id"`
	ClientSecret       string `ini:"client_secret"`
}

// LoadConfig 加载配置文件并返回 Config 结构体
func LoadConfig(path string) *Config {
	cfg, err := ini.Load(path)
	if err != nil {
		log.Fatalf("Fail to read file: %v", err)
	}

	var config Config
	err = cfg.MapTo(&config)
	if err != nil {
		log.Fatal("Fail to map configuration: ", err)
	}

	return &config
}
