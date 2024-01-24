package handlers

import (
	"net/http"
	"server/auth"
	"server/logging"
	"strconv"
	// 引入其他需要的包
)

// HandleOAuthCallback 处理 OAuth 回调请求
func HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		// 处理错误情况：缺少授权码
		http.Error(w, "Authorization code is missing", http.StatusBadRequest)
		return
	}

	// 请求 Access Token
	token, err := auth.RequestAccessToken(code, cfg)
	if err != nil {
		// 处理错误情况：无法获取 Access Token
		logging.ConsoleLogger.Printf("An error occurred: %v\n", err)
		http.Error(w, "Failed to get access token", http.StatusInternalServerError)
		return
	}

	// 将 Access Token 设置到 Cookie
	http.SetCookie(w, &http.Cookie{
		Name:  "access_token",
		Value: token,
		Path:  "/",
	})

	// 重定向到主页
	http.Redirect(w, r, "http://"+cfg.BindIP+":"+strconv.Itoa(cfg.Port), http.StatusSeeOther)
}
