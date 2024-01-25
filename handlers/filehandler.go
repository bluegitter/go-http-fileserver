package handlers

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
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
	// // 转储请求的全部信息
	// dump, err := httputil.DumpRequest(r, true)
	// if err != nil {
	// 	fmt.Fprintf(w, "Error: %v", err)
	// 	return
	// }

	// // 打印到服务器的控制台
	// fmt.Printf("Request: %v\n", string(dump))

	// 设置 CORS 头
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 如果是预检请求，发送适当的头并结束响应
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Secret-Key")
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.URL.Path == "/" {
		// 如果请求的是根路径，返回欢迎页面
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<h1>Welcome to the Go HTTP Server</h1>")
		return
	}

	if isAliyunOSSRequest(r) {
		if checkOssSignature(r) {
			ossHandle(w, r)
			return
		}
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
	internalHandle(w, r)
}

func ossHandle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	lrw := NewLoggingResponseWriter(w)

	switch r.Method {
	case "PUT":
		ossUploadFile(w, r)
	case "GET":
		ossDownloadFile(w, r)
	case "DELETE":
		ossDeleteFile(w, r)
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

func ossUploadFile(w http.ResponseWriter, r *http.Request) {
	bucketName, ok := extractBucketName(r)

	if !ok {
		sendJSONResponse(w, http.StatusInternalServerError, createResponse(http.StatusInternalServerError, "Could not create file", "", 0, time.Time{}, time.Time{}))
		return
	}

	// Create directory and file
	objectName := r.URL.Path
	filePath := getFilePath(cfg.DataDir + "/" + bucketName + "/" + path.Base(objectName))
	fmt.Printf("filePath: %s\n", filePath)

	os.MkdirAll(path.Dir(filePath), os.ModePerm) // Create directories if they don't exist

	dst, err := os.Create(filePath)
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, createResponse(http.StatusInternalServerError, "Could not create file", "", 0, time.Time{}, time.Time{}))
		return
	}
	defer dst.Close()

	// Copy file content and calculate checksum
	hash := sha256.New()
	// tee := io.TeeReader(r.Body, hash)

	_, err = io.Copy(dst, r.Body)
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

type Response struct {
	XMLName    xml.Name  `xml:"Response"`
	Status     int       `xml:"Status"`
	Message    string    `xml:"Message"`
	Checksum   string    `xml:"Checksum"`
	Size       int64     `xml:"Size"`
	CreateTime time.Time `xml:"CreateTime"`
	ModTime    time.Time `xml:"ModTime"`
}

func sendXMLResponse(w http.ResponseWriter, statusCode int, resp Response) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(statusCode)

	xmlData, err := xml.MarshalIndent(resp, "", "  ")
	fmt.Printf("%s\n", xmlData)
	if err != nil {
		// 处理错误，可能返回一个错误响应
		http.Error(w, "Error generating XML", http.StatusInternalServerError)
		return
	}

	w.Write(xmlData)
}

func ossDeleteFile(w http.ResponseWriter, r *http.Request) {
	bucketName, ok := extractBucketName(r)

	if !ok {
		sendXMLResponse(w, http.StatusNotFound, Response{
			Status:  http.StatusNotFound,
			Message: "File not found",
			// 设置其他字段
			Checksum:   "",
			Size:       0,
			CreateTime: time.Time{},
			ModTime:    time.Time{},
		})
		return
	}

	// Create directory and file
	objectName := r.URL.Path
	filePath := getFilePath(cfg.DataDir + "/" + bucketName + "/" + path.Base(objectName))
	fmt.Printf("filePath: %s\n", filePath)

	// Delete file
	err := os.Remove(filePath)
	if err != nil {
		sendXMLResponse(w, http.StatusNotFound, Response{
			Status:  http.StatusNotFound,
			Message: "Could not create file",
			// 设置其他字段
			Checksum:   "",
			Size:       0,
			CreateTime: time.Time{},
			ModTime:    time.Time{},
		})
		return
	}

	sendXMLResponse(w, http.StatusNoContent, Response{
		Status:  http.StatusNoContent,
		Message: "File deleted successfully",
		// 设置其他字段
		Checksum:   "",
		Size:       0,
		CreateTime: time.Time{},
		ModTime:    time.Time{},
	})
}
func internalHandle(w http.ResponseWriter, r *http.Request) {
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

func isAliyunOSSRequest(r *http.Request) bool {
	// 检查 Authorization 头是否以 "OSS" 开头
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "OSS") {
		return true
	}

	// 检查 Host 头是否包含 "aliyuncs.com"
	hostHeader := r.Header.Get("Host")
	if strings.Contains(hostHeader, "aliyuncs.com") {
		return true
	}

	return false
}

// extractBucketName 从 Host 头部提取 bucketName
func extractBucketName(r *http.Request) (string, bool) {
	host := r.Host
	parts := strings.SplitN(host, ".", 2)

	if len(parts) < 2 || !strings.HasSuffix(parts[1], "aliyuncs.com") {
		return "", false // 不符合预期格式或不是阿里云的域名
	}

	return parts[0], true
}

func checkOssSignature(r *http.Request) bool {
	method := r.Method
	contentType := r.Header.Get("Content-Type")
	gmtDate := r.Header.Get("X-Oss-Date")
	objectName := r.URL.Path
	bucketName, ok := extractBucketName(r)

	if !ok {
		return false
	}

	signature := generateSignature(cfg.ClientID, cfg.ClientSecret, method, contentType, gmtDate, bucketName, objectName)
	authHeader := r.Header.Get("Authorization")

	if signature == authHeader {
		return true
	}
	return false
}

// generateSignature 生成阿里云 OSS 签名
func generateSignature(accessKeyId, accessKeySecret, method, contentType, gmtDate, bucketName, objectName string) string {
	signatureString := fmt.Sprintf("%s\n\n%s\n%s\nx-oss-date:%s\n/%s%s", method, contentType, gmtDate, gmtDate, bucketName, objectName)

	// 使用 HMAC-SHA1 进行签名
	hmacSha1 := hmac.New(sha1.New, []byte(accessKeySecret))
	hmacSha1.Write([]byte(signatureString))

	// 对签名结果进行 Base64 编码
	signatureEncoded := base64.StdEncoding.EncodeToString(hmacSha1.Sum(nil))

	// 构造完整的 Authorization 头部值
	return fmt.Sprintf("OSS %s:%s", accessKeyId, signatureEncoded)
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
func ossDownloadFile(w http.ResponseWriter, r *http.Request) {
	bucketName, ok := extractBucketName(r)

	if !ok {
		sendJSONResponse(w, http.StatusInternalServerError, createResponse(http.StatusInternalServerError, "Could not open file", "", 0, time.Time{}, time.Time{}))
		return
	}

	// Create directory and file
	objectName := r.URL.Path
	filePath := getFilePath(cfg.DataDir + "/" + bucketName + "/" + path.Base(objectName))
	fmt.Printf("filePath: %s\n", filePath)

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
	cleanedPath := path.Clean("/" + urlPath)
	realPath := path.Join(cfg.DataDir, "buckets", cleanedPath)
	absolutePath, err := filepath.Abs(realPath)
	if err != nil {
		logging.ConsoleLogger.Printf("Error converting relative path to absolute path: %+v\n", err)
		return realPath
	}
	return absolutePath
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
