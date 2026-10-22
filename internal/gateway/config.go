package gateway

import (
	"errors"
	"regexp"
	"time"
)

// Config is immutable after New. No request value can raise these ceilings.
type Config struct {
	ContentType      string   `json:"content_type"`
	Purpose          string   `json:"purpose"`
	MaxBytes         int64    `json:"max_bytes"`
	MaxConcurrent    int      `json:"max_concurrent"`
	MaxStaged        int      `json:"max_staged"`
	MaxPerSubject    int      `json:"max_per_subject"`
	MaxDepth         int      `json:"max_depth"`
	MaxTokens        int      `json:"max_tokens"`
	MaxStringBytes   int      `json:"max_string_bytes"`
	RequestSeconds   int      `json:"request_seconds"`
	RetentionSeconds int      `json:"retention_seconds"`
	TicketSeconds    int      `json:"ticket_seconds"`
	Origins          []string `json:"origins"`
}

func DefaultConfig() Config {
	return Config{ContentType: "application/json", Purpose: "account-import", MaxBytes: 1 << 20, MaxConcurrent: 2, MaxStaged: 16, MaxPerSubject: 2, MaxDepth: 16, MaxTokens: 10000, MaxStringBytes: 4096, RequestSeconds: 15, RetentionSeconds: 300, TicketSeconds: 60}
}
func (c Config) Validate() error {
	if c.ContentType != "application/json" && c.ContentType != "application/octet-stream" {
		return errors.New("invalid local content type")
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`).MatchString(c.Purpose) {
		return errors.New("invalid local purpose")
	}
	if c.MaxBytes < 1 || c.MaxBytes > 1<<20 || c.MaxConcurrent < 1 || c.MaxConcurrent > 2 || c.MaxStaged < 1 || c.MaxStaged > 16 || c.MaxPerSubject < 1 || c.MaxPerSubject > 2 || c.MaxDepth < 1 || c.MaxDepth > 16 || c.MaxTokens < 1 || c.MaxTokens > 10000 || c.MaxStringBytes < 1 || c.MaxStringBytes > 4096 || c.RequestSeconds < 1 || c.RequestSeconds > 15 || c.RetentionSeconds < 1 || c.RetentionSeconds > 300 || c.TicketSeconds < 1 || c.TicketSeconds > 60 {
		return errors.New("config exceeds aegis hard ceilings")
	}
	return nil
}
func (c Config) Deadline() time.Duration { return time.Duration(c.RequestSeconds) * time.Second }
