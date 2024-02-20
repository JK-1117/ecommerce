package main

import (
	"log"
	"os"

	logging "github.com/JK-1117/go-htmx-base/internal/logger"
	"github.com/JK-1117/go-htmx-base/internal/server"
	"github.com/joho/godotenv"
)

func main() {
	env := os.Getenv("APP_ENV")
	if env != "" {
		env = "." + env
	}
	err := godotenv.Load(".env" + env)
	if err != nil {
		log.Fatal(err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT env variable not found.")
	}

	_, err = logging.GetLogger()
	if err != nil {
		log.Fatal(err)
	}

	app := server.NewApp()
	app.Run(port)
}
