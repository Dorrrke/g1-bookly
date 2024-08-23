package config

import (
	"flag"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadConfig(t *testing.T) {
	type want struct {
		cfg Conifg
	}
	type test struct {
		name     string
		flags    []string
		envSetup func()
		want     want
	}

	tests := []test{
		{
			name:  "Test ReadConfig func; Test 1",
			flags: []string{"test", "--addr", "testaddr", "--debug"},
			want: want{
				cfg: Conifg{
					Addr:      "testaddr",
					DBAddr:    defaultDbDSN,
					MPath:     defaultMigratePath,
					DebugFlag: true,
				},
			},
		},
		{
			name:  "Test ReadConfig func; Test 2",
			flags: []string{"test", "--addr", "testaddr", "--db", "dbaddr", "--m", "mPath"},
			want: want{
				cfg: Conifg{
					Addr:      "testaddr",
					DBAddr:    "dbaddr",
					MPath:     "mPath",
					DebugFlag: false,
				},
			},
		},
		{
			name:  "Test ReadConfig func; Test 3",
			flags: []string{"test", "-debug"},
			envSetup: func() {
				t.Setenv("SERVER_ADDR", "envSrvAddr")
				t.Setenv("DB_DSN", "envDbAddr")
			},
			want: want{
				cfg: Conifg{
					Addr:      "envSrvAddr",
					DBAddr:    "envDbAddr",
					MPath:     defaultMigratePath,
					DebugFlag: true,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log.Println(len(tc.flags))
			if len(tc.flags) != 0 {
				os.Args = tc.flags
				flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
			}
			if tc.envSetup != nil {
				tc.envSetup()
				defer os.Unsetenv("SERVER_ADDR")
				defer os.Unsetenv("DB_DSN")
			}
			cfg := ReadConfig()
			assert.Equal(t, tc.want.cfg, cfg)
		})
	}
}
