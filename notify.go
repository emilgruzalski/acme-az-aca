package main

import (
	"fmt"
	"log/slog"
	"net/smtp"
)

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

func sendErrorNotification(cfg config, subject, message string) error {
	if !cfg.NotifyEnabled {
		return nil
	}
	if cfg.SMTPHost == "" || cfg.SMTPUsername == "" || cfg.SMTPPassword == "" {
		return fmt.Errorf("incomplete SMTP configuration")
	}

	auth := smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPHost)
	body := fmt.Sprintf("Subject: %s\r\n"+
		"From: %s\r\n"+
		"To: %s\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", subject, cfg.SMTPFrom, cfg.SMTPTo, message)

	if err := smtp.SendMail(
		cfg.SMTPHost+":"+cfg.SMTPPort,
		auth,
		cfg.SMTPFrom,
		[]string{cfg.SMTPTo},
		[]byte(body),
	); err != nil {
		return fmt.Errorf("sending notification email: %w", err)
	}

	slog.Info("notification email sent", "to", cfg.SMTPTo)
	return nil
}
