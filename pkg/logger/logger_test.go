package logger

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestColorize(t *testing.T) {
	tests := []struct {
		name      string
		colorCode int
		input     string
		want      string
	}{
		{"Red", red, "error", "\033[31merror\033[0m"},
		{"Green", green, "success", "\033[32msuccess\033[0m"},
		{"Blue", blue, "info", "\033[34minfo\033[0m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := colorize(tt.colorCode, tt.input); got != tt.want {
				t.Errorf("colorize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandler_Enabled(t *testing.T) {
	h := NewHandler(&slog.HandlerOptions{Level: slog.LevelInfo})
	tests := []struct {
		name  string
		level slog.Level
		want  bool
	}{
		{"Debug", slog.LevelDebug, false},
		{"Info", slog.LevelInfo, true},
		{"Warn", slog.LevelWarn, true},
		{"Error", slog.LevelError, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := h.Enabled(context.Background(), tt.level); got != tt.want {
				t.Errorf("Handler.Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandler_Handle(t *testing.T) {
	t.Skip("Handler.Handle() is not implemented yet")
	var buf bytes.Buffer
	h := &Handler{
		h: slog.NewJSONHandler(&buf, nil),
		b: &bytes.Buffer{},
		m: &sync.Mutex{},
	}

	ctx := context.Background()
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "test message", 0)
	r.AddAttrs(slog.String("key", "value"))

	err := h.Handle(ctx, r)
	if err != nil {
		t.Fatalf("Handler.Handle() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("Handler.Handle() output doesn't contain message, got: %v", output)
	}
	if !strings.Contains(output, `"key":"value"`) {
		t.Errorf("Handler.Handle() output doesn't contain attribute, got: %v", output)
	}
}

func TestNewSlogger(t *testing.T) {
	tests := []struct {
		name    string
		options []LoggerOption
		wantLvl slog.Level
		wantFmt Format
	}{
		{"Default", nil, slog.LevelInfo, FormatText},
		{"Debug", []LoggerOption{WithDebug()}, slog.LevelDebug, FormatText},
		{"JSON", []LoggerOption{WithFormat(FormatJSON)}, slog.LevelInfo, FormatJSON},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewSlogger(tt.options...)
			h := logger.Handler()

			// Check level
			if !h.Enabled(context.Background(), tt.wantLvl) {
				t.Errorf("NewSlogger() logger not enabled for level %v", tt.wantLvl)
			}

			// Check format
			switch tt.wantFmt {
			case FormatJSON:
				if _, ok := h.(*slog.JSONHandler); !ok {
					t.Errorf("NewSlogger() handler is not JSONHandler")
				}
			case FormatText:
				if _, ok := h.(*Handler); !ok {
					t.Errorf("NewSlogger() handler is not custom Handler")
				}
			}
		})
	}
}

func TestMarshalLevel(t *testing.T) {
	tests := []struct {
		name  string
		level slog.Level
		want  string
	}{
		{"Debug", slog.LevelDebug, "DEBUG"},
		{"Info", slog.LevelInfo, "INFO"},
		{"Warn", slog.LevelWarn, "WARNING"},
		{"Error", slog.LevelError, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := slog.Attr{
				Key:   slog.LevelKey,
				Value: slog.AnyValue(tt.level),
			}

			result := marshalLevel(nil)(nil, attr)

			if result.Key != "severity" {
				t.Errorf("marshalLevel() key = %v, want %v", result.Key, "severity")
			}

			if result.Value.String() != tt.want {
				t.Errorf("marshalLevel() value = %v, want %v", result.Value, tt.want)
			}
		})
	}
}
