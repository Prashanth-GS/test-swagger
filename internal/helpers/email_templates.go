package helpers

import "github.com/sendgrid/sendgrid-go/helpers/mail"

// FromAddress Constant
var FromAddress = mail.NewEmail("GSOP", "noreply@gsop.com")

// RegiserConfEmailSubject Constant
const RegiserConfEmailSubject = "[GSOP] Please Confirm Your Email Address"

// RegiserConfEmailContent Constant
const RegiserConfEmailContent = "Please follow the instructions to confirm your email address"

// GetRegisterConfTemplate Function
func GetRegisterConfTemplate(link string) string {
	return `
		We are happy to see you register to GSOP!!
		<br /><br />
		Please confirm your email address by clicking the link below:
		<br /><br />
		` + link + `
		<br /><br />
		If you don’t use this link within 30 mins, it will expire. To get a new link, visit https://www.google.com/ and reregister.
		<br /><br />
		Thanks,
		<br />
		Your friends at GSOP
	`
}

// RPEmailSubject Constant
const RPEmailSubject = "[GSOP] Please Reset your Password"

// RPEmailContent Constant
const RPEmailContent = "Please follow the instructions to reset your password"

// GetResetPasswordTemplate Function
func GetResetPasswordTemplate(link string) string {
	return `
		We heard that you lost your GSOP password. Sorry about that!
		<br /><br />
		But don’t worry! You can use the following link to reset your password:
		<br /><br />
		` + link + `
		<br /><br />
		If you don’t use this link within 30 mins, it will expire. To get a new password reset link, visit https://www.google.com/
		<br /><br />
		Thanks,
		<br />
		Your friends at GSOP
	`
}
