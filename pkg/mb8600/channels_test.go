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
	"reflect"
	"strings"
	"testing"
)

const (
	downstreamResponse = "1^Locked^QAM256^20^531.0^ 2.8^45.1^0^0^|+|2^Locked^QAM256^13^489.0^ 3.1^45.4^0^0^|+|3^Locked^QAM256^14^495.0^ 3.0^45.5^0^0^|+|4^Locked^QAM256^15^501.0^ 3.0^41.6^0^0^|+|5^Locked^QAM256^16^507.0^ 3.0^40.7^0^0^|+|6^Locked^QAM256^17^513.0^ 3.1^43.3^0^0^|+|7^Locked^QAM256^18^519.0^ 3.0^45.4^0^0^|+|8^Locked^QAM256^19^525.0^ 3.0^45.4^0^0^|+|9^Locked^QAM256^21^537.0^ 2.6^45.3^10^0^|+|10^Locked^QAM256^22^543.0^ 2.3^44.9^14^0^|+|11^Locked^QAM256^23^549.0^ 2.3^45.0^11^0^|+|12^Locked^QAM256^24^555.0^ 1.9^44.7^0^0^|+|13^Locked^QAM256^25^561.0^ 2.1^44.8^0^0^|+|14^Locked^QAM256^26^567.0^ 2.3^44.5^0^0^|+|15^Locked^QAM256^27^573.0^ 2.4^44.8^0^0^|+|16^Locked^QAM256^28^579.0^ 2.6^44.8^0^0^|+|17^Locked^QAM256^29^585.0^ 2.6^44.9^0^0^|+|18^Locked^QAM256^30^591.0^ 2.8^45.0^0^0^|+|19^Locked^QAM256^31^597.0^ 2.8^45.0^0^0^|+|20^Locked^QAM256^32^603.0^ 2.8^39.5^0^0^|+|21^Locked^QAM256^33^609.0^ 2.9^44.3^0^0^|+|22^Locked^QAM256^34^615.0^ 3.1^45.2^0^0^|+|23^Locked^QAM256^35^621.0^ 3.2^44.9^28138575^44205737^|+|24^Locked^QAM256^36^627.0^ 3.4^30.9^261314250^787815699^|+|25^Locked^QAM256^37^633.0^ 3.3^37.4^103208291^126451293^|+|26^Locked^QAM256^38^639.0^ 3.8^45.3^4147493^506585^|+|27^Locked^QAM256^39^645.0^ 3.8^45.3^0^0^|+|28^Locked^QAM256^40^651.0^ 4.0^45.4^0^0^|+|29^Locked^QAM256^41^657.0^ 4.0^45.3^0^0^|+|30^Locked^QAM256^42^663.0^ 3.9^45.1^9^0^|+|31^Locked^QAM256^43^669.0^ 3.6^45.1^17^0^|+|32^Locked^QAM256^44^675.0^ 3.8^44.5^9^0^|+|33^Locked^OFDM PLC^193^957.0^-0.7^43.0^-1565968621^150^"
	upstreamResponse   = "1^Locked^SC-QAM^4^5120^35.6^56.0^"
)

var (
	expDownstreamChannel = &DownstreamChannel{
		Channel:           1,
		ChannelID:         20,
		LockStatus:        "Locked",
		Modulation:        "QAM256",
		Frequency:         531.0,
		SignalToNoise:     45.1,
		Power:             2.8,
		CorrectedErrors:   0,
		UncorrectedErrors: 0,
	}

	expUpstreamChannel = &UpstreamChannel{
		Channel:     1,
		ChannelID:   4,
		LockStatus:  "Locked",
		Power:       56.0,
		SymbolRate:  5120,
		Frequency:   35.6,
		ChannelType: "SC-QAM",
	}
)

func TestNewDownstreamChannelsFromResponse(t *testing.T) {
	type args struct {
		response string
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{"empty", args{""}, 0, false},
		{"valid", args{downstreamResponse}, 33, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDownstreamChannelsFromResponse(tt.args.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDownstreamChannelsFromResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.want {
				t.Errorf("len(NewDownstreamChannelsFromResponse()) = %v, want %v", len(got), tt.want)
			}
		})
	}
}

func TestNewDownstreamChannelFromLine(t *testing.T) {
	line := strings.Split(downstreamResponse, "|+|")[0]
	type args struct {
		line string
	}
	tests := []struct {
		name    string
		args    args
		want    *DownstreamChannel
		wantErr bool
	}{
		{
			"valid",
			args{line},
			expDownstreamChannel,
			false,
		},
		{
			"invalid - too many",
			args{fmt.Sprintf("%s^test^", line)},
			nil,
			true,
		},
		{
			"invalid - too few",
			args{strings.Join(strings.Split(line, "^")[:5], "^")},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDownstreamChannelFromLine(tt.args.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDownstreamChannelFromLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDownstreamChannelFromLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewUpstreamChannelsFromResponse(t *testing.T) {
	type args struct {
		response string
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			"no channels",
			args{""},
			0,
			false,
		},
		{
			"single channel",
			args{upstreamResponse},
			1,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewUpstreamChannelsFromResponse(tt.args.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewUpstreamChannelsFromResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.want {
				t.Errorf("len(NewUpstreamChannelsFromResponse()) = %v, want %v", len(got), tt.want)
			}
		})
	}
}

func TestNewUpstreamChannelFromLine(t *testing.T) {
	type args struct {
		line string
	}
	tests := []struct {
		name    string
		args    args
		want    *UpstreamChannel
		wantErr bool
	}{
		{"valid", args{upstreamResponse}, expUpstreamChannel, false},
		{"invalid - too many", args{fmt.Sprintf("%stest^", upstreamResponse)}, nil, true},
		{
			"invalid - too few",
			args{strings.Join(strings.Split(upstreamResponse, "^")[:4], "^")},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewUpstreamChannelFromLine(tt.args.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewUpstreamChannelFromLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewUpstreamChannelFromLine() = %v, want %v", got, tt.want)
			}
		})
	}
}
