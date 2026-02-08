package logging

import (
	"fmt"
	"log/slog"
	"os"
)

type SamlLoggerAdapter struct {
	Logger *slog.Logger
}

func (a *SamlLoggerAdapter) Printf(format string, v ...any) {
	a.Logger.Info(fmt.Sprintf(format, v...))
}

func (a *SamlLoggerAdapter) Fatalf(format string, v ...any) {
	a.Logger.Error(fmt.Sprintf(format, v...))
	os.Exit(1)
}
