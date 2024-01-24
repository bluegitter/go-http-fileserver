package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/ini.v1"
)

const maxLogFiles = 10

var (
	currentLogFile int
	lastLogDate    time.Time
	logMutex       sync.Mutex
	fileLogger     *log.Logger // 用于文件的日志记录器
	consoleLogger  *log.Logger // 用于控制台的日志记录器
)

var (
	secretKey string
	port      int
)

// ANSI 颜色代码
const (
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorReset   = "\033[0m"
)

type Config struct {
	BindIP             string `ini:"bind_ip"`
	Port               int    `ini:"port"`
	SecretKey          string `ini:"secret_key"`
	OAuthTokenURL      string `ini:"oauth_token_url"`
	OAuthCheckTokenURL string `ini:"oauth_check_token_url"`
	OAuthAuthorizeURL  string `ini:"oauth_authorize_url"`
	ClientID           string `ini:"client_id"`
	ClientSecret       string `ini:"client_secret"`
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	length      int
	wroteHeader bool // 新增字段，用于跟踪是否已经写入头部
}

func init() {
	// 初始化 fileLogger，不包含颜色代码
	logFile, err := os.OpenFile("server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Error opening server.log: %v", err)
	}
	fileLogger = log.New(logFile, "", log.LstdFlags)

	// 初始化 consoleLogger，包含颜色代码
	consoleLogger = log.New(os.Stdout, "", log.LstdFlags)

	lastLogDate = time.Now().Truncate(24 * time.Hour)
}

func main() {
	cfg, err := ini.Load("server.conf")
	if err != nil {
		consoleLogger.Fatal("Fail to read file: ", err)
	}

	var config Config
	err = cfg.MapTo(&config)
	if err != nil {
		log.Fatal("Fail to map configuration: ", err)
	}

	secretKey := config.SecretKey
	if secretKey == "" {
		secretKey = generateSecretKey()
	}
	consoleLogger.Printf("Using Generated Secret Key: "+colorGreen+"%s"+colorReset, secretKey)

	port := strconv.Itoa(config.Port)
	consoleLogger.Printf("Starting http file server on "+colorGreen+"%s:%s"+colorReset, config.BindIP, port)

	http.HandleFunc("/", handler(config))
	http.HandleFunc("/callback", callbackHandler(config))
	http.ListenAndServe(fmt.Sprintf("%s:%s", config.BindIP, port), nil)

}

func rotateLogFile() error {
	logMutex.Lock()
	defer logMutex.Unlock()

	// 计算新的日志文件名
	currentLogFile = (currentLogFile % maxLogFiles) + 1
	newLogFileName := fmt.Sprintf("server%d.log", currentLogFile)

	// 重命名当前的 server.log
	err := os.Rename("server.log", newLogFileName)
	if err != nil {
		return err
	}

	// 创建一个新的 server.log 文件
	file, err := os.Create("server.log")
	if err != nil {
		return err
	}
	file.Close()

	// 更新 lastLogDate 为今天
	lastLogDate = time.Now().Truncate(24 * time.Hour)
	return nil
}

func checkLogRotation() {
	today := time.Now().Truncate(24 * time.Hour)
	if lastLogDate.Before(today) {
		err := rotateLogFile()
		if err != nil {
			log.Fatalf("Error rotating log file: %v", err)
		}
	}
}

func generateSecretKey() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		panic("generate SecretKey error.")
	}

	for i, v := range b {
		b[i] = charset[v%byte(len(charset))]
	}

	return "sk-" + string(b)
}

func handler(config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if !checkSecretKey(r) {
			if !checkAccessToken(r, config) {
				// sendJSONResponse(w, http.StatusForbidden, map[string]interface{}{"code": http.StatusForbidden, "error": "Access denied: invalid X-Access-Token in http header, or the 'X-Secret-Key' header is missing."})
				// return
				// 发送一个重定向响应
				redirectURL := config.OAuthAuthorizeURL + "?client_id=" + config.ClientID + "&response_type=code&redirect_uri=" + "http://" + config.BindIP + ":" + strconv.Itoa(config.Port) + "/callback"
				http.Redirect(w, r, redirectURL, http.StatusSeeOther)
				return
			}
		}
		start := time.Now()
		lrw := NewLoggingResponseWriter(w)

		switch r.Method {
		case "PUT":
			uploadFile(w, r)
		case "GET":
			downloadFile(w, r)
		case "DELETE":
			deleteFile(w, r)
		default:
			http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
		}

		duration := time.Since(start)
		method := coloredMethod(r.Method)
		// 从 r.RemoteAddr 中提取 IP 地址
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// 如果无法解析 IP 地址，使用原始的 RemoteAddr
			ip = r.RemoteAddr
		}

		consoleLogger.Printf("%s [%s] %s %d %d %d\n",
			colorCyan+ip+colorReset, method, colorYellow+r.URL.Path+colorReset, http.StatusOK, duration.Milliseconds(), lrw.length)
	}
}

func NewLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK, 0, false}
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	if !lrw.wroteHeader {
		lrw.WriteHeader(http.StatusOK)
	}
	size, err := lrw.ResponseWriter.Write(b)
	lrw.length += size
	return size, err
}

func (lrw *loggingResponseWriter) WriteHeader(statusCode int) {
	if lrw.wroteHeader {
		return // 如果头部已经写入，直接返回
	}
	lrw.ResponseWriter.WriteHeader(statusCode)
	lrw.statusCode = statusCode
	lrw.wroteHeader = true // 设置标志，表示头部已经写入
}

func coloredMethod(method string) string {
	uppercaseMethod := strings.ToUpper(method)

	switch uppercaseMethod {
	case "GET":
		return colorBlue + uppercaseMethod + colorReset
	case "POST":
		return colorGreen + uppercaseMethod + colorReset
	case "PUT":
		return colorYellow + uppercaseMethod + colorReset
	case "DELETE":
		return colorRed + uppercaseMethod + colorReset
	default:
		return colorMagenta + uppercaseMethod + colorReset
	}
}

func callbackHandler(config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			// 处理错误情况：缺少授权码
			http.Error(w, "Authorization code is missing", http.StatusBadRequest)
			return
		}

		// 请求 Access Token
		token, err := requestAccessToken(code, config)
		if err != nil {
			// 处理错误情况：无法获取 Access Token
			consoleLogger.Printf("An error occurred: %v\n", err)
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
		http.Redirect(w, r, "http://"+config.BindIP+":"+strconv.Itoa(config.Port), http.StatusSeeOther)
	}
}
func requestAccessToken(code string, config Config) (string, error) {
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

	println(req.URL.String())
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
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.AccessToken, nil
}

func checkSecretKey(r *http.Request) bool {
	// 从 HTTP 头部或查询参数中获取密钥
	key := r.Header.Get("X-Secret-Key")

	if key == "" || key != secretKey {
		return false
	}
	return true
}

func checkAccessToken(r *http.Request, config Config) bool {
	// 尝试从 URL 查询参数获取 token
	token := r.URL.Query().Get("token")

	// 如果 URL 中没有 token，尝试从 HTTP 头部获取
	if token == "" {
		token = r.Header.Get("X-Access-Token")
	}

	// 如果 HTTP 头部中也没有 token，尝试从 Cookie 获取
	if token == "" {
		cookie, err := r.Cookie("access_token")
		if err == nil {
			token = cookie.Value
		}
	}

	return validateTokenWithExternalService(token, config)
}

func validateTokenWithExternalService(token string, config Config) bool {
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

	consoleLogger.Printf("check_token: "+colorGreen+"%s"+colorReset, string(body))

	if resp.StatusCode != http.StatusOK {
		return false
	}
	return true
}

func uploadFile(w http.ResponseWriter, r *http.Request) {
	// Parse Multipart Form
	r.ParseMultipartForm(10 << 20) // Limit upload size

	file, _, err := r.FormFile("file")
	if err != nil {
		sendJSONResponse(w, http.StatusBadRequest, createResponse(http.StatusBadRequest, "Invalid file", "", 0, time.Time{}, time.Time{}))
		return
	}
	defer file.Close()

	// Create directory and file
	filePath := getFilePath(r.URL.Path)
	os.MkdirAll(path.Dir(filePath), os.ModePerm) // Create directories if they don't exist

	dst, err := os.Create(filePath)
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, createResponse(http.StatusInternalServerError, "Could not create file", "", 0, time.Time{}, time.Time{}))
		return
	}
	defer dst.Close()

	// Copy file content and calculate checksum
	hash := sha256.New()
	tee := io.TeeReader(file, hash)

	_, err = io.Copy(dst, tee)
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, createResponse(http.StatusInternalServerError, "Error while saving file", "", 0, time.Time{}, time.Time{}))
		return
	}

	chksum := hex.EncodeToString(hash.Sum(nil))

	// Get file info for size, creation and modification times
	info, err := os.Stat(filePath)
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, createResponse(http.StatusInternalServerError, "Error getting file info", chksum, 0, time.Time{}, time.Time{}))
		return
	}

	sendJSONResponse(w, http.StatusOK, createResponse(http.StatusOK, "File uploaded successfully", chksum, info.Size(), info.ModTime(), info.ModTime()))
}

func downloadFile(w http.ResponseWriter, r *http.Request) {
	filePath := getFilePath(r.URL.Path)

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		consoleLogger.Printf("Error opening file: %+v\n", filePath)
		sendJSONResponse(w, http.StatusNotFound, createResponse(http.StatusNotFound, "File not found", "", 0, time.Time{}, time.Time{}))
		return
	}
	defer file.Close()

	// Get file info for size, creation and modification times
	_, err = file.Stat()
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, createResponse(http.StatusInternalServerError, "Error getting file info", "", 0, time.Time{}, time.Time{}))
		return
	}

	// Set headers for download
	w.Header().Set("Content-Disposition", "attachment; filename="+path.Base(filePath))
	w.Header().Set("Content-Type", "application/octet-stream")

	// Stream file content
	io.Copy(w, file)
}

func deleteFile(w http.ResponseWriter, r *http.Request) {
	filePath := getFilePath(r.URL.Path)

	// Delete file
	err := os.Remove(filePath)
	if err != nil {
		sendJSONResponse(w, http.StatusNotFound, createResponse(http.StatusNotFound, "File not found", "", 0, time.Time{}, time.Time{}))
		return
	}

	sendJSONResponse(w, http.StatusOK, createResponse(http.StatusOK, "File deleted successfully", "", 0, time.Time{}, time.Time{}))
}

func getFilePath(urlPath string) string {
	// Split URL path to get bucket-name and object-name
	parts := strings.SplitN(urlPath[1:], "/", 2) // Remove leading slash and split
	if len(parts) != 2 {
		return "" // Or some error handling
	}
	bucketName := parts[0]
	objectName := parts[1]

	// Construct file path
	return path.Join("buckets", bucketName, objectName)
}

func sendJSONResponse(w http.ResponseWriter, statusCode int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(response)
}

func createResponse(status int, message string, chksum string, size int64, createTime time.Time, modTime time.Time) map[string]interface{} {
	return map[string]interface{}{
		"status":     status,
		"message":    message,
		"checksum":   chksum,
		"size":       size,
		"createTime": createTime.Format(time.RFC3339),
		"modTime":    modTime.Format(time.RFC3339),
	}
}
