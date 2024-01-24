package logging

import (
	"log"
	"os"
)

var FileLogger *log.Logger

func InitializeFileLogger(logFilePath string) {
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Error opening log file: %s, %v", logFilePath, err)
	}

	FileLogger = log.New(logFile, "", log.LstdFlags)
}
