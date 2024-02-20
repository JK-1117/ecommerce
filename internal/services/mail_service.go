package services

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"
	"sync"

	logging "github.com/JK-1117/go-htmx-base/internal/logger"
)

type MailService struct {
	host   string
	port   string
	auth   smtp.Auth
	sender string
}

type MailHeader struct {
	Subject string
	Sender  string
	To      []string
	Cc      []string
	Bcc     []string
}

var service *MailService
var lock = &sync.Mutex{}

func GetMailService() *MailService {
	if service == nil {
		lock.Lock()
		defer lock.Unlock()

		if service == nil {

			host := os.Getenv("SMTP_HOST")
			port := os.Getenv("SMTP_PORT")
			a := smtp.PlainAuth(
				"",
				os.Getenv("SMTP_USERNAME"),
				os.Getenv("SMTP_PASSWORD"),
				host,
			)

			sender := os.Getenv("SMTP_SENDER")

			service = &MailService{
				host:   host,
				port:   port,
				auth:   a,
				sender: sender,
			}
			return service
		} else {
			return service
		}
	} else {
		return service
	}
}

func (s *MailService) SendMail(header MailHeader, body string) error {
	logger, _ := logging.GetLogger()
	sender := s.sender
	if header.Sender != "" {
		sender = header.Sender
	}

	msg := []byte(header.String() +
		"\r\n\r\n" +
		body + "\r\n")

	logger.App.Info(
		fmt.Sprintf("Sending mail - host:%s port:%s sender:%s to:%v msg:%s",
			s.host, s.port, sender, header.To, msg))
	err := smtp.SendMail(
		fmt.Sprintf("%s:%s", s.host, s.port),
		s.auth,
		sender,
		header.To,
		msg,
	)
	return err
}

func (h *MailHeader) String() string {
	var header [8]string
	i := 0

	if h.Subject != "" {
		str := "Subject: " + h.Subject
		header[i] = str
		i++
	}
	if h.Sender != "" {
		str := "Sender: " + h.Sender
		header[i] = str
		i++
	}
	if len(h.To) > 0 {
		str := "To: " + strings.Join(h.To, ",")
		header[i] = str
		i++
	}
	if len(h.Cc) > 0 {
		str := "cc: " + strings.Join(h.Cc, ",")
		header[i] = str
		i++
	}
	if len(h.Bcc) > 0 {
		str := "Bcc: " + strings.Join(h.Bcc, ",")
		header[i] = str
		i++
	}
	header[i] = "MIME-Version: 1.0"
	i++
	header[i] = "Content-Type: text/html; charset=utf-8"
	i++
	header[i] = "Content-Transfer-Encoding: 7bit"
	i++

	return strings.Join(header[:i], "\r\n")
}
