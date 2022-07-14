package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

// RunWithSysSignal run with system signal
func RunWithSysSignal(clearFunc func(os.Signal)) {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.WithField("prefix", "root.run_with_sys_signal").
			Infof("system signal: %s", sig)
		if clearFunc != nil {
			clearFunc(sig)
		}
		done <- true
		os.Exit(1)
	}()
	<-done
}

// InitGlobalVars init global vars
func InitGlobalVars() {
	envlevel := viper.GetString("logger_level")
	if envlevel != "" {
		GlobalEnvs.LoggerLevel = envlevel
	}
	logLevel, err := logrus.ParseLevel(GlobalEnvs.LoggerLevel)
	if err != nil {
		logrus.WithField("prefix", "root.init_global_vars").
			Fatalf("unsupport log level: %s", GlobalEnvs.LoggerLevel)
	}
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logLevel)
	formatter := new(prefixed.TextFormatter)
	logrus.SetFormatter(formatter)
	if GlobalEnvs.DataCenter == "" {
		GlobalEnvs.DataCenter = viper.GetString("data_center")
	}
}
