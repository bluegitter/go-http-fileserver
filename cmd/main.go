package main

import (
	"fmt"
	"net/http"
	"server/config"
	"server/handlers"
	"server/logging"
	"server/util"
	"strconv"
	// Other imports...
)

var (
	secretKey string
	port      int
)

func main() {
	cfg := config.LoadConfig("server.conf")
	handlers.SetConfig(*cfg)
	logging.InitializeFileLogger("server.log")
	logging.InitializeConsoleLogger()

	secretKey := cfg.SecretKey
	if secretKey == "" {
		secretKey = util.GenerateSecretKey()
	}
	logging.ConsoleLogger.Printf("Using Generated Secret Key: "+logging.ColorGreen+"%s"+logging.ColorReset, secretKey)

	// Setup HTTP server and routes
	http.HandleFunc("/", handlers.HandleMain)
	http.HandleFunc("/callback", handlers.HandleOAuthCallback)
	// Other route setups...

	port := strconv.Itoa(cfg.Port)
	// Start the server
	logging.ConsoleLogger.Printf("Starting http file server on "+logging.ColorGreen+"%s:%s"+logging.ColorReset, cfg.BindIP, port)
	http.ListenAndServe(fmt.Sprintf("%s:%s", cfg.BindIP, port), nil)

}
