package rexec

import (
	"errors"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	ADJ_FREQ_MAX = 512000
	THRESHOLD    = 100000000 //100ms
)

func SetClock(t time.Time) error {
	tv := syscall.NsecToTimeval(t.UnixNano())
	if err := syscall.Settimeofday(&tv); err != nil {
		return errors.New("settimeofday: " + err.Error())
	}
	logrus.WithField("prefix", "rexec").Debugf(
		"set clock success: %s", t.Format(time.RFC3339Nano))
	return nil
}

// UpdateTime faile to arm
// func UpdateTime(netTime time.Time, offset time.Duration) error {
// 	offsetInt := int(offset.Nanoseconds())
// 	offfsetSec := math.Abs(float64(offset.Seconds()))
// 	offsetNsec := math.Abs(float64(offset))
// 	logrus.WithField("prefix", "rexec").Debugf(
// 		"set clock offset: %f,%f", offfsetSec, offsetNsec)
// 	if offfsetSec > 1 || offsetNsec > THRESHOLD {
// 		return SetClock(netTime)
// 	}
// 	ap := 2
// 	ai := 10
// 	observed_drift := 0
// 	adj := 0
// 	observed_drift += offsetInt / ai
// 	if observed_drift > ADJ_FREQ_MAX {
// 		observed_drift = ADJ_FREQ_MAX
// 	} else if observed_drift < -ADJ_FREQ_MAX {
// 		observed_drift = -ADJ_FREQ_MAX
// 	}
// 	adj = offsetInt/ap + observed_drift
// 	freq := int64(-adj * ((1 << 16) / 1000))
// 	tx := &syscall.Timex{
// 		Modes: 0x0002,
// 		Freq:  freq,
// 	}
// 	status, err := syscall.Adjtimex(tx)
// 	if err != nil {
// 		return err
// 	}
// 	if status != 0 {
// 		return fmt.Errorf("failed to sync [%d]: %d", status, freq)
// 	}
// 	logrus.WithField("prefix", "rexec").Debugf(
// 		"adjtime freq success: %d", freq)
// 	return nil
// }
