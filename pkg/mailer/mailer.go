package mailer

import (
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

func (r *resendMailer) SendMail(to string, id string, data map[string]interface{}) error {
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
