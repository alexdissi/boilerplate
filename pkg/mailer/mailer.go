package mailer

import (
	"my_project/pkg/logger"

	"github.com/resend/resend-go/v3"
)

type resendMailer struct {
	client *resend.Client
	from   string
}

func NewResendMailer(apiKey string, from string) Mailer {
	client := resend.NewClient(apiKey)
	return &resendMailer{client: client, from: from}
}

func (r *resendMailer) SendMail(to string, id string, data map[string]any) error {
	params := &resend.SendEmailRequest{
		From: r.from,
		To:   []string{to},
		Template: &resend.EmailTemplate{
			Id:        id,
			Variables: data,
		},
	}

	_, err := r.client.Emails.Send(params)
	return err
}

func (r *resendMailer) SendMailAsync(to string, id string, data map[string]any, operationName string) {
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("Panic in email goroutine", "operation", operationName, "panic", rec)
			}
		}()

		err := r.SendMail(to, id, data)
		if err != nil {
			logger.Error("Failed to send email", "operation", operationName, "to", to, "template", id, "error", err)
		}
	}()
}
