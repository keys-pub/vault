package client

import (
	pkglog "log"
)

var logger = NewLogger(ErrLevel)

// SetLogger sets logger for the package.
func SetLogger(l Logger) {
	logger = l
}

// Logger interface used in this package.
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warningf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
}

// LogLevel ...
type LogLevel int

const (
	// DebugLevel ...
	DebugLevel LogLevel = 3
	// InfoLevel ...
	InfoLevel LogLevel = 2
	// WarnLevel ...
	WarnLevel LogLevel = 1
	// ErrLevel ...
	ErrLevel LogLevel = 0
)

// NewLogger ...
func NewLogger(lev LogLevel) Logger {
	return &defaultLog{Level: lev}
}

func (l LogLevel) String() string {
	switch l {
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case WarnLevel:
		return "warn"
	case ErrLevel:
		return "err"
	default:
		return ""
	}
}

func init() {
	pkglog.SetFlags(pkglog.LstdFlags | pkglog.Lmicroseconds)
}

type defaultLog struct {
	Level LogLevel
}

func (l defaultLog) Debugf(format string, args ...interface{}) {
	if l.Level >= 3 {
		pkglog.Printf("[DEBG] "+format+"\n", args...)
	}
}

func (l defaultLog) Infof(format string, args ...interface{}) {
	if l.Level >= 2 {
		pkglog.Printf("[INFO] "+format+"\n", args...)
	}
}

func (l defaultLog) Warningf(format string, args ...interface{}) {
	if l.Level >= 1 {
		pkglog.Printf("[WARN] "+format+"\n", args...)
	}
}

func (l defaultLog) Errorf(format string, args ...interface{}) {
	if l.Level >= 0 {
		pkglog.Printf("[ERR]  "+format+"\n", args...)
	}
}

func (l defaultLog) Fatalf(format string, args ...interface{}) {
	pkglog.Fatalf(format, args...)
}
