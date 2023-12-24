/*
Copyright 2023 Thomas Helander

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package mb8600

import (
	"fmt"
	"strconv"
	"strings"
)

type DownstreamChannel struct {
	Channel           int
	ChannelID         int
	LockStatus        string
	Modulation        string
	Frequency         float64
	Power             float64
	SignalToNoise     float64
	CorrectedErrors   float64
	UncorrectedErrors float64
}

func NewDownstreamChannelsFromResponse(response string) ([]*DownstreamChannel, error) {
	var channels []*DownstreamChannel

	for _, line := range strings.Split(response, "|+|") {
		if len(line) == 0 {
			continue
		}

		if channel, err := NewDownstreamChannelFromLine(line); err != nil {
			return nil, err
		} else {
			channels = append(channels, channel)
		}
	}

	return channels, nil
}

// Returns true if the channel has the same properties as channel o; false otherwise.
func (c *DownstreamChannel) Equal(o *DownstreamChannel) bool {
	return c.Channel == o.Channel &&
		c.ChannelID == o.ChannelID &&
		c.LockStatus == o.LockStatus &&
		c.Modulation == o.Modulation &&
		c.Frequency == o.Frequency &&
		c.Power == o.Power &&
		c.SignalToNoise == o.SignalToNoise &&
		c.CorrectedErrors == o.CorrectedErrors &&
		c.UncorrectedErrors == o.UncorrectedErrors
}

func NewDownstreamChannelFromLine(line string) (*DownstreamChannel, error) {
	parts := strings.Split(line, "^")
	if len(parts) != 10 {
		return nil, fmt.Errorf("invalid number of parts in downstream channel line: %d", len(parts))
	}

	// Strip whitespace from all parts.
	for idx := range parts {
		parts[idx] = strings.Trim(parts[idx], " ")
	}

	channel, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, err
	}

	lockStatus := parts[1]
	modulation := parts[2]
	channelId, err := strconv.Atoi(parts[3])
	if err != nil {
		return nil, err
	}

	frequency, err := strconv.ParseFloat(parts[4], 64)
	if err != nil {
		return nil, err
	}

	power, err := strconv.ParseFloat(parts[5], 64)
	if err != nil {
		return nil, err
	}

	snr, err := strconv.ParseFloat(parts[6], 64)
	if err != nil {
		return nil, err
	}

	corrected, err := strconv.ParseFloat(parts[7], 64)
	if err != nil {
		return nil, err
	}

	uncorrected, err := strconv.ParseFloat(parts[8], 64)
	if err != nil {
		return nil, err
	}

	return &DownstreamChannel{
		Channel:           channel,
		ChannelID:         channelId,
		LockStatus:        lockStatus,
		Modulation:        modulation,
		Frequency:         frequency,
		Power:             power,
		SignalToNoise:     snr,
		CorrectedErrors:   corrected,
		UncorrectedErrors: uncorrected,
	}, nil
}

type UpstreamChannel struct {
	Channel     int
	ChannelID   int
	LockStatus  string
	ChannelType string
	SymbolRate  float64
	Frequency   float64
	Power       float64
}

// Returns true if the channel has the same properties as channel o; false otherwise.
func (c *UpstreamChannel) Equal(o *UpstreamChannel) bool {
	return c.Channel == o.Channel &&
		c.ChannelID == o.ChannelID &&
		c.LockStatus == o.LockStatus &&
		c.ChannelType == o.ChannelType &&
		c.Frequency == o.Frequency &&
		c.Power == o.Power &&
		c.SymbolRate == o.SymbolRate
}

func NewUpstreamChannelsFromResponse(response string) ([]*UpstreamChannel, error) {
	var channels []*UpstreamChannel

	for _, line := range strings.Split(response, "|+|") {
		if len(line) == 0 {
			continue
		}

		if channel, err := NewUpstreamChannelFromLine(line); err != nil {
			return nil, err
		} else {
			channels = append(channels, channel)
		}
	}

	return channels, nil
}

func NewUpstreamChannelFromLine(line string) (*UpstreamChannel, error) {
	parts := strings.Split(line, "^")
	if len(parts) != 8 {
		return nil, fmt.Errorf("invalid number of parts in upstream channel line: %d", len(parts))
	}

	// Strip whitespace from all parts.
	for idx := range parts {
		parts[idx] = strings.Trim(parts[idx], " ")
	}

	channel, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, err
	}

	lockStatus := parts[1]
	channelType := parts[2]
	channelId, err := strconv.Atoi(parts[3])
	if err != nil {
		return nil, err
	}

	symbolRate, err := strconv.ParseFloat(parts[4], 64)
	if err != nil {
		return nil, err
	}

	frequency, err := strconv.ParseFloat(parts[5], 64)
	if err != nil {
		return nil, err
	}

	power, err := strconv.ParseFloat(parts[6], 64)
	if err != nil {
		return nil, err
	}

	return &UpstreamChannel{
		Channel:     channel,
		ChannelID:   channelId,
		LockStatus:  lockStatus,
		ChannelType: channelType,
		SymbolRate:  symbolRate,
		Frequency:   frequency,
		Power:       power,
	}, nil
}
