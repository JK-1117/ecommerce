package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/JK-1117/go-htmx-base/internal/database"
	logging "github.com/JK-1117/go-htmx-base/internal/logger"
	"github.com/robfig/cron/v3"
)

type CronJob struct {
	q       *database.Queries
	cron    *cron.Cron
	outFile *os.File
}

func NewCron(q *database.Queries) *CronJob {
	my, _ := time.LoadLocation("Asia/Kuala_Lumpur")
	logger, _ := logging.GetLogger()

	cFile, err := os.OpenFile("./logs/schedule.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Cron.Err(err.Error())
	}
	cWriter := io.MultiWriter(os.Stdout, cFile)
	cLogger := log.New(cWriter, "cron: ", log.LstdFlags)

	c := cron.New(
		cron.WithLogger(
			cron.VerbosePrintfLogger(cLogger),
		),
		cron.WithLocation(my),
	)

	return &CronJob{
		q:       q,
		cron:    c,
		outFile: cFile,
	}
}

func (job *CronJob) Start() {
	job.cron.AddFunc("@daily", job.CleanInvalidSession)
	job.cron.AddFunc("@monthly", job.RotateLogFiles)

	job.cron.Start()
}

func (job *CronJob) Stop() context.Context {
	job.outFile.Close()
	return job.cron.Stop()
}

func (job *CronJob) CleanInvalidSession() {
	logger, _ := logging.GetLogger()
	logger.Cron.Info("STARTING CleanInvalidSession")
	if err := job.q.DeleteExpiredSession(context.Background()); err != nil {
		logger.Cron.Err(fmt.Sprintf("CleanInvalidSession: %v", err))
		return
	}
	logger.Cron.Info("COMPLETED CleanInvalidSession")
}

func (job *CronJob) RotateLogFiles() {
	if os.Getenv("APP_ENV") != "production" {
		return
	}
	logger, _ := logging.GetLogger()
	logger.Cron.Info("STARTING RotateLogFiles")
	if err := logger.RotateLogFiles(); err != nil {
		logger.Cron.Err(fmt.Sprintf("RotateLogFiles: %v", err))
		return
	}
	logger.Cron.Info("COMPLETED RotateLogFiles")
}
