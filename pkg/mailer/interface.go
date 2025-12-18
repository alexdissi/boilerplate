package mailer

type Mailer interface {
	SendMail(to string, id string, data map[string]interface{}) error
}
