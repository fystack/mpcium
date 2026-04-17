package logger

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

var Log zerolog.Logger

func Init(env string, debug bool) {
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	if env != "production" {
		Log = zerolog.New(
			zerolog.ConsoleWriter{Out: os.Stderr, NoColor: false, TimeFormat: "2006-01-02 15:04:05.000"},
		).With().Timestamp().Logger()
	} else {
		Log = zerolog.New(os.Stdout).With().Timestamp().Logger()
	}
}

// Debug logs a debug message.
func Debug(msg string, keyValues ...interface{}) {
	// ctx needs to be even because it's a series of key/value pairs
	// no one wants to check for errors on logging functions,
	// so instead of erroring on bad input, we'll just make sure
	// that things are the right length and users can fix bugs
	// when they see the output looks wrong

	l := len(keyValues)
	if l%2 != 0 {
		Log.Warn().Caller().Interface("Unknown Key", keyValues).Msgf("%s ([Wrong logger.Info usage] Provided args to logger.Info must be a series of key/value pairs)", msg)
	} else {
		ctx := Log.Debug()

		for i := 0; i < len(keyValues); i += 2 {
			key, value := keyValues[i].(string), keyValues[i+1]
			ctx = ctx.Interface(key, value)
		}

		ctx.Msg(msg)
	}
}

// Info logs an info message.

func Info(msg string, keyValues ...interface{}) {

	// ctx needs to be even because it's a series of key/value pairs
	// no one wants to check for errors on logging functions,
	// so instead of erroring on bad input, we'll just make sure
	// that things are the right length and users can fix bugs
	// when they see the output looks wrong

	l := len(keyValues)
	if l%2 != 0 {
		Log.Warn().Caller().Interface("Unknown Key", keyValues).Msgf("%s ([Wrong logger.Info usage] Provided args to logger.Info must be a series of key/value pairs)", msg)
	} else {
		ctx := Log.Info()

		for i := 0; i < len(keyValues); i += 2 {
			key, value := keyValues[i].(string), keyValues[i+1]
			ctx = ctx.Interface(key, value)
		}

		ctx.Msg(msg)
	}

}

func Warn(msg string, keyValues ...interface{}) {

	// ctx needs to be even because it's a series of key/value pairs
	// no one wants to check for errors on logging functions,
	// so instead of erroring on bad input, we'll just make sure
	// that things are the right length and users can fix bugs
	// when they see the output looks wrong

	l := len(keyValues)
	if l%2 != 0 {
		Log.Warn().Caller().Interface("Unknown Key", keyValues).Msgf("%s ([Wrong logger.Info usage] Provided args to logger.Info must be a series of key/value pairs)", msg)
	} else {
		ctx := Log.Warn()

		for i := 0; i < len(keyValues); i += 2 {
			key, value := keyValues[i].(string), keyValues[i+1]
			ctx = ctx.Interface(key, value)
		}

		ctx.Msg(msg)
	}

}

// Info logs an info message.
func Infof(format string, v ...interface{}) {
	Log.Info().Msgf(format, v...)
}

// Error logs an error message.
func Error(msg string, err error, keyValues ...interface{}) {
	if len(keyValues)%2 != 0 {
		panic("keyValues must be a list of key/value pairs")
	}

	ctx := Log.Error()
	for i := 0; i < len(keyValues); i += 2 {
		key, value := keyValues[i].(string), keyValues[i+1]
		ctx = ctx.Interface(key, value)
	}

	// Skip one additional frame so caller points to the code using logger.Error,
	// not this wrapper function itself.
	ctx.Caller(1).Stack().Err(err).Msg(msg)
}

// Fatal logs a fatal message and exits the program.
func Fatal(msg string, err error) {
	Log.Fatal().Err(err).Msg(msg)
}

// Panic logs a panic message and panics.
func Panic(msg string, err error) {
	Log.Panic().Err(err).Msg(msg)
}
