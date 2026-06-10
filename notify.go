package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"time"
)

// smtpTimeout bounds the whole SMTP session; notifications are sent from the
// renewal loop, so a hung server must not stall certificate processing.
const smtpTimeout = 30 * time.Second

// notifyOnError sends an SMTP error notification when enabled, and logs
// (but does not propagate) any failure delivering it.
func notifyOnError(cfg config, subject, message string) {
	if !cfg.NotifyEnabled {
		return
	}
	if err := sendErrorNotification(cfg, subject, message); err != nil {
		slog.Error("notification failed", "error", err)
	}
}

// sendErrorNotification speaks SMTP by hand instead of smtp.SendMail because
// SendMail dials and reads with no timeout.
func sendErrorNotification(cfg config, subject, message string) error {
	if cfg.SMTPHost == "" || cfg.SMTPUsername == "" || cfg.SMTPPassword == "" {
		return fmt.Errorf("incomplete SMTP configuration")
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(cfg.SMTPHost, cfg.SMTPPort), smtpTimeout)
	if err != nil {
		return fmt.Errorf("connecting to SMTP server: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(smtpTimeout)); err != nil {
		return fmt.Errorf("setting SMTP deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("SMTP handshake: %w", err)
	}
	defer func() { _ = client.Close() }()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: cfg.SMTPHost}); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}

	auth := smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPHost)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP auth: %w", err)
	}
	if err := client.Mail(cfg.SMTPFrom); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %w", err)
	}
	if err := client.Rcpt(cfg.SMTPTo); err != nil {
		return fmt.Errorf("SMTP RCPT TO: %w", err)
	}

	body := fmt.Sprintf("Subject: %s\r\n"+
		"From: %s\r\n"+
		"To: %s\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", subject, cfg.SMTPFrom, cfg.SMTPTo, message)

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %w", err)
	}
	if _, err := wc.Write([]byte(body)); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("finishing message: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("SMTP QUIT: %w", err)
	}

	slog.Info("notification email sent", "to", cfg.SMTPTo)
	return nil
}
