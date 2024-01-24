package logging

import "strings"

// ANSI 颜色代码
const (
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorReset   = "\033[0m"
)

func ColoredMethod(method string) string {
	uppercaseMethod := strings.ToUpper(method)

	switch uppercaseMethod {
	case "GET":
		return ColorBlue + uppercaseMethod + ColorReset
	case "POST":
		return ColorGreen + uppercaseMethod + ColorReset
	case "PUT":
		return ColorYellow + uppercaseMethod + ColorReset
	case "DELETE":
		return ColorRed + uppercaseMethod + ColorReset
	default:
		return ColorMagenta + uppercaseMethod + ColorReset
	}
}
