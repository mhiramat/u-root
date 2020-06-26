// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/beevik/ntp"
	"github.com/u-root/u-root/pkg/rtc"
)

// pollNTP queries the specified NTP server.
// On error the query is repeated infinitally.
func pollNTP() (time.Time, error) {
	p := filepath.Join(dataMountPoint, ntpServerFile)
	bytes, err := ioutil.ReadFile(p)
	if err != nil {
		reboot("NTP server URLs: %v", err)
	}
	var servers []string
	if err = json.Unmarshal(bytes, &servers); err != nil {
		return time.Time{}, err
	}
	for _, server := range servers {
		info("Query NTP server %s", server)
		t, err := ntp.Time(server)
		if err == nil {
			return t, nil
		}
		debug("NTP error: %v", err)
	}
	//time.Sleep(3 * time.Second)
	return time.Time{}, errors.New("No NTP server resposnes")
}

// validateSystemTime sets RTC and OS time according to
// realtime clock, timestamp and ntp
func validateSystemTime(builtTime time.Time, useNetwork bool) error {
	rtc, err := rtc.OpenRTC()
	if err != nil {
		return fmt.Errorf("opening RTC failed: %v", err)
	}
	rtcTime, err := rtc.Read()
	if err != nil {
		return fmt.Errorf("reading RTC failed: %v", err)
	}

	info("Systemtime: %v", rtcTime.UTC())
	if rtcTime.UTC().Before(builtTime.UTC()) {
		info("Systemtime is invalid: %v", rtcTime.UTC())
		var newTime time.Time
		if useNetwork {
			info("Receive time via NTP")
			newTime, err = pollNTP()
			if err != nil {
				return err
			}
			if newTime.UTC().Before(builtTime.UTC()) {
				return errors.New("NTP spoof may happened")
			}
		} else {
			info("Configured not to use network to update time")
			info("Set system time to timestamp of hostvars.json")
			info("WARNING: System time will not be up to date!")
			newTime = builtTime
		}
		info("Update RTC to %v", newTime.UTC())
		err = rtc.Set(newTime)
		if err != nil {
			return fmt.Errorf("writing RTC failed: %v", err)
		}
		reboot("Set system time. Need to reboot.")
	}
	return nil
}
