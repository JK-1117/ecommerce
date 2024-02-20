package logger

// https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
func RedBg(log string) string {
	return "\u001B[41m " + log + " \u001B[0m"
}

func GreenBg(log string) string {
	return "\u001B[42m " + log + " \u001B[0m"
}

func YellowBg(log string) string {
	return "\u001B[43m " + log + " \u001B[0m"
}

func BlueBg(log string) string {
	return "\u001B[44m " + log + " \u001B[0m"
}

func MagentaBg(log string) string {
	return "\u001B[45m " + log + " \u001B[0m"
}

func CyanBg(log string) string {
	return "\u001B[46m " + log + " \u001B[0m"
}

func Red(log string) string {
	return "\u001B[31m" + log + "\u001B[0m"
}

func Green(log string) string {
	return "\u001B[32m" + log + "\u001B[0m"
}

func Yellow(log string) string {
	return "\u001B[33m" + log + "\u001B[0m"
}

func Blue(log string) string {
	return "\u001B[34m" + log + "\u001B[0m"
}

func Magenta(log string) string {
	return "\u001B[35m" + log + "\u001B[0m"
}

func Cyan(log string) string {
	return "\u001B[36m" + log + "\u001B[0m"
}
