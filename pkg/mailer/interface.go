package mailer

type Mailer interface {
	SendMail(to string, id string, data map[string]any) error
	SendMailAsync(to string, id string, data map[string]any, operationName string)
}
