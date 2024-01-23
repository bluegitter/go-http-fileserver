package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"
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
	var port string

	flag.StringVar(&secretKey, "sk", "", "Secret key for authentication")
	flag.StringVar(&port, "p", "8080", "Port to listen on")
	flag.Parse()

	// 如果没有提供 SecretKey，则生成一个
	if secretKey == "" {
		secretKey = generateSecretKey()
		fmt.Printf("Using Generated Secret Key: %s\n", secretKey)
	}

	consoleLogger.Printf(colorGreen+"Starting http file server on :%s\n"+colorReset, port)

	http.HandleFunc("/", handler)
	http.ListenAndServe(fmt.Sprintf(":%s", port), nil)

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

func handler(w http.ResponseWriter, r *http.Request) {
	if errMsg := checkSecretKey(r); errMsg != "" {
		sendJSONResponse(w, http.StatusForbidden, map[string]interface{}{"status": http.StatusForbidden, "error": errMsg})
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
}

func checkSecretKey(r *http.Request) string {
	// 从 HTTP 头部或查询参数中获取密钥
	key := r.Header.Get("X-Secret-Key")

	if key == "" || key != secretKey {
		return "Access Denied: The 'X-Secret-Key' header is missing or contains an invalid value in the HTTP request"
	}
	return ""
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
