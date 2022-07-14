package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// GlobalEnvs global environments
var GlobalEnvs struct {
	LoggerLevel string
	EtcdAddr    string
	DataCenter  string
}

// ServerEnvs server environments
var ServerEnvs struct {
	BindEth       string
	BindAddr      []string
	BindAddrSplit string

	TrustedPath string
	CertPath    string
	PrivkeyPath string
}

// ValidateStringVar validate string var
func ValidateStringVar(v *string, envName string, required bool) error {
	if *v == "" {
		*v = viper.GetString(envName)
		if *v == "" {
			if required {
				return fmt.Errorf("undefine var [%s]", envName)
			}
			log.WithFields(log.Fields{
				"prefix": "root.validate_string_var",
			}).Debugf("env [%s] not define,use nil or default value", envName)
		}
	}
	return nil
}

// ValidateUint32Var validate int var
func ValidateUint32Var(v *uint32, envName string, required bool) error {
	if *v == 0 {
		*v = uint32(viper.GetInt32(envName))
		if *v == 0 {
			if required {
				return fmt.Errorf("undefine var [%s]", envName)
			}
			log.WithFields(log.Fields{
				"prefix": "root.validate_string_var",
			}).Debugf("env [%s] not define,use nil or default value", envName)
		}
	}
	return nil
}

// ValidateInt8Var validate int var
func ValidateInt8Var(v *int8, envName string, required bool) error {
	if *v == 0 {
		*v = int8(viper.GetInt32(envName))
		if *v == 0 {
			if required {
				return fmt.Errorf("undefine var [%s]", envName)
			}
			log.WithFields(log.Fields{
				"prefix": "root.validate_string_var",
			}).Debugf("env [%s] not define,use nil or default value", envName)
		}
	}
	return nil
}

// SetEnvBoolV set env bool value
func SetEnvBoolV(v *bool, envName string) (err error) {
	if bv := viper.GetString(envName); bv != "" {
		*v, err = strconv.ParseBool(bv)
	}
	return err
}

//InitBindAddr init server bind addr
func InitBindAddr() {
	bindIps, err := GetInterfaceIPAddress(ServerEnvs.BindEth)
	ServerEnvs.BindAddrSplit = strings.Join(bindIps, ",")
	if err != nil {
		logrus.WithField("prefix", "kmc").Fatalf(
			"query ethernet interface with prefix [%s] failed: %s",
			ServerEnvs.BindEth, err.Error())
	}
	ServerEnvs.BindAddr = bindIps
}
