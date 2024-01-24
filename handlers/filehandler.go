package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"server/auth"
	"server/config"
	"server/logging"
	"strconv"
	"strings"
	"time"
	// 引入其他需要的包
)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	length      int
	wroteHeader bool // 新增字段，用于跟踪是否已经写入头部
}

var cfg config.Config

func SetConfig(c config.Config) {
	cfg = c
}

func HandleMain(w http.ResponseWriter, r *http.Request) {
	// 设置 CORS 头
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 如果是预检请求，发送适当的头并结束响应
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Secret-Key")
		w.WriteHeader(http.StatusOK)
		return
	}

	if !checkSecretKey(r) {
		if !checkAccessToken(r, cfg) {
			// sendJSONResponse(w, http.StatusForbidden, map[string]interface{}{"code": http.StatusForbidden, "error": "Access denied: invalid X-Access-Token in http header, or the 'X-Secret-Key' header is missing."})
			// return
			// 发送一个重定向响应
			redirectURL := cfg.OAuthAuthorizeURL + "?client_id=" + cfg.ClientID + "&response_type=code&redirect_uri=" + "http://" + cfg.BindIP + ":" + strconv.Itoa(cfg.Port) + "/callback"
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}
	}
	start := time.Now()
	lrw := NewLoggingResponseWriter(w)

	if r.URL.Path == "/" {
		// 如果请求的是根路径，返回欢迎页面
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<h1>Welcome to the Go HTTP Server</h1>")
		return
	}

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
	method := logging.ColoredMethod(r.Method)
	// 从 r.RemoteAddr 中提取 IP 地址
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// 如果无法解析 IP 地址，使用原始的 RemoteAddr
		ip = r.RemoteAddr
	}

	logging.ConsoleLogger.Printf("%s [%s] %s %d %d %d\n",
		logging.ColorCyan+ip+logging.ColorReset, method, logging.ColorYellow+r.URL.Path+logging.ColorReset, http.StatusOK, duration.Milliseconds(), lrw.length)
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
		logging.ConsoleLogger.Printf("Error opening file: %+v\n", filePath)
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

func checkSecretKey(r *http.Request) bool {
	// 从 HTTP 头部或查询参数中获取密钥
	key := r.Header.Get("X-Secret-Key")

	if key == "" || key != cfg.SecretKey {
		return false
	}
	return true
}

func checkAccessToken(r *http.Request, config config.Config) bool {
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

	return auth.ValidateToken(token, config)
}
