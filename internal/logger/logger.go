package logger

import (
	"os"
	"strconv"

	"github.com/rs/zerolog"
)

func SetupLogger(debug bool) *zerolog.Logger {
	var zlog zerolog.Logger
	zerolog.TimestampFieldName = "Time"
	zerolog.LevelFieldName = "Level"
	zerolog.CallerMarshalFunc = func(_ uintptr, file string, line int) string {
		short := file
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				short = file[i+1:]
				break
			}
		}
		file = short
		return file + ":" + strconv.Itoa(line)
	}
	if debug {
		zlog = zerolog.New(os.Stdout).Level(zerolog.DebugLevel).With().Timestamp().Caller().Logger()
		return &zlog
	}
	zlog = zerolog.New(os.Stdout).Level(zerolog.InfoLevel).With().Timestamp().Caller().Logger()
	return &zlog
}
