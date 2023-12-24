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
	"testing"

	"github.com/prometheus/common/promlog"
)

const (
	publicKey = "jXesCa9ek/lI0/R4TNdr"
	challenge = "q9l0h9ieIXKwJlEtTXps"
	address   = "192.168.100.1"
	username  = "admin"
	password  = "motorola"
	timestamp = 1703361406202
)

var (
	promlogConfig = &promlog.Config{}
	logger        = promlog.New(promlogConfig)
)

type MockTimestamper struct {
	Value int64
}

func (t *MockTimestamper) Timestamp() int64 {
	return t.Value
}

func Test_md5Sum(t *testing.T) {
	type args struct {
		key  string
		data string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"test",
			args{fmt.Sprintf("%s%s", publicKey, password), challenge},
			"376888B58EBBAA4207D9D4E898C2E504",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := md5Sum(tt.args.key, tt.args.data); got != tt.want {
				t.Errorf("md5Sum() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMotoClient_hnapAuth(t *testing.T) {
	clientNoPkey := NewMotoClientWithTimestamper(
		address,
		username,
		password,
		logger,
		&MockTimestamper{
			Value: timestamp,
		},
	)

	clientWithPkey := NewMotoClientWithTimestamper(
		address,
		username,
		password,
		logger,
		&MockTimestamper{
			Value: timestamp,
		},
	)
	clientWithPkey.SetPrivateKey(
		md5Sum(fmt.Sprintf("%s%s", publicKey, password), challenge),
	)

	tests := []struct {
		name   string
		c      *MotoClient
		action string
		want   string
	}{
		{
			"login_no_pkey",
			clientNoPkey,
			"Login",
			fmt.Sprintf("B390D71563C4C02619AF9D61F9D942AF %d", timestamp),
		},
		{
			"login_with_pkey",
			clientWithPkey,
			"Login",
			fmt.Sprintf("FD695E907F6790F96AD8EF0FB19BCF32 %d", timestamp),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.hnapAuth(tt.action); got != tt.want {
				t.Errorf("MotoClient.hnapAuth() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMotoClient_SetPrivateKey(t *testing.T) {
	c := NewMotoClient(
		address,
		username,
		password,
		logger,
	)
	tests := []struct {
		name string
		c    *MotoClient
		key  string
		want string
	}{
		{"test", c, "test", "test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.SetPrivateKey(tt.key); err != nil {
				t.Errorf("MotoClient.SetPrivateKey() error = %v, wantErr %v", err, nil)
			}

			if got, err := tt.c.GetPrivateKey(); err != nil || got != tt.want {
				t.Errorf("MotoClient.GetPrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
