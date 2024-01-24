package logging

import (
	"log"
	"os"
)

var ConsoleLogger *log.Logger

func InitializeConsoleLogger() {
	ConsoleLogger = log.New(os.Stdout, "", log.LstdFlags)
}
