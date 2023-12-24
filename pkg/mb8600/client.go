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
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

const (
	soapNamespace = "http://purenetworks.com/HNAP1/"

	privateKeyCookieName   = "PrivateKey"
	defaultPrivateKeyValue = "withoutloginkey"

	uidCookieName   = "uid"
	defaultUidValue = ""
)

var (
	knownActions = []string{
		"Login",
		"GetHomeConnection",
		"GetHomeAddress",
		"GetMotoStatusSoftware",
		"GetMotoStatusLog",
		"GetMotoLagStatus",
		"GetMotoStatusConnectionInfo",
		"GetMotoStatusDownstreamChannelInfo",
		"GetMotoStatusStartupSequence",
		"GetMotoStatusUpstreamChannelInfo",
	}
)

type MotoClient struct {
	Address  string
	Username string
	Password string
	Logger   log.Logger

	client      http.Client
	timestamper Timestamper
}

type Timestamper interface {
	Timestamp() int64
}

type DefaultTimestamper struct{}

func (t *DefaultTimestamper) Timestamp() int64 {
	return time.Now().UnixMilli()
}

func md5Sum(key, data string) string {
	h := hmac.New(md5.New, []byte(key))
	io.WriteString(h, data)
	return fmt.Sprintf("%X", h.Sum(nil))
}

// Returns a new client with the specified Timestamper class.
//
// The client will be configured to skip SSL certificate verification as the cable
// modem uses a self-signed certificate.
func NewMotoClientWithTimestamper(address, username, password string, logger log.Logger, timestamper Timestamper) *MotoClient {
	c := MotoClient{
		Address:  address,
		Username: username,
		Password: password,
		Logger:   logger,
	}

	insecureTransport := http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	c.client = http.Client{
		Jar:       jar,
		Transport: &insecureTransport,
	}
	c.timestamper = timestamper

	return &c
}

// Returns a new client with the default Timestamper class.
//
// The client will be configured to skip SSL certificate verification as the cable
// modem uses a self-signed certificate.
func NewMotoClient(address, username, password string, logger log.Logger) *MotoClient {
	return NewMotoClientWithTimestamper(
		address,
		username,
		password,
		logger,
		&DefaultTimestamper{},
	)
}

func (c *MotoClient) do(action string, params map[string]string) (map[string]string, error) {
	if !slices.Contains(knownActions, action) {
		return nil, fmt.Errorf("invalid action: %s", action)
	}

	if params == nil {
		params = map[string]string{}
	}

	actionUri := fmt.Sprintf("%s%s", soapNamespace, action)
	data := map[string]map[string]string{action: params}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"SOAPAction":   actionUri,
		"HNAP_AUTH":    c.hnapAuth(action),
	}

	req, err := http.NewRequest(http.MethodPost, c.GetHNAPURI(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, nil
	}

	for name, value := range headers {
		req.Header.Set(name, value)
	}

	level.Debug(c.Logger).Log(
		"msg", "making request",
		"uri", c.GetHNAPURI(),
		"headers", fmt.Sprintf("%s", headers),
		"data", fmt.Sprintf("%s", data),
	)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	level.Debug(c.Logger).Log("status code", resp.StatusCode, "status", resp.Status)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("action, %s, received non-OK status code: %d", action, resp.StatusCode)
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil
	}

	var respJsonData map[string]map[string]string
	if err = json.Unmarshal(respData, &respJsonData); err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%sResponse", action)
	if value, ok := respJsonData[key]; !ok {
		return nil, fmt.Errorf("no response from modem")
	} else {
		return value, nil
	}
}

func (c *MotoClient) hnapAuth(action string) string {
	ts := c.timestamper.Timestamp()
	data := fmt.Sprintf("%d%s%s", ts, soapNamespace, action)
	pkey, err := c.GetPrivateKey()
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s %d", md5Sum(pkey, data), ts)
}

func (c *MotoClient) getCookie(name, path, defaultValue string) (string, error) {
	url, err := c.GetHNAPURL()
	if err != nil {
		return "", err
	}

	for _, cookie := range c.client.Jar.Cookies(url) {
		if cookie.Name == name && (cookie.Path == path || cookie.Path == "") {
			return cookie.Value, nil
		}
	}

	return defaultValue, nil
}

func (c *MotoClient) setCookie(name, value, path string) error {
	url, err := c.GetHNAPURL()
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:  name,
		Value: value,
		Path:  path,
	}
	c.client.Jar.SetCookies(url, []*http.Cookie{cookie})

	return nil
}

// Return the private key used for communicating with the modem, or the
// default private key value used when logging in.
func (c *MotoClient) GetPrivateKey() (string, error) {
	return c.getCookie(privateKeyCookieName, "/", defaultPrivateKeyValue)
}

// Return the client UID.
func (c *MotoClient) GetUID() (string, error) {
	return c.getCookie(uidCookieName, "/", defaultUidValue)
}

// Set the private key.
func (c *MotoClient) SetPrivateKey(key string) error {
	return c.setCookie(privateKeyCookieName, key, "/")
}

// Set the client UID.
func (c *MotoClient) SetUID(uid string) error {
	return c.setCookie(uidCookieName, uid, "/")
}

// Returns the API endpoint URI as a string.
func (c *MotoClient) GetHNAPURI() string {
	return fmt.Sprintf("https://%s/HNAP1/", c.Address)
}

// Returns the API endpoint URI as a url.URL object.
func (c *MotoClient) GetHNAPURL() (*url.URL, error) {
	url, err := url.Parse(c.GetHNAPURI())
	if err != nil {
		return nil, err
	}
	return url, nil
}

// Logs in to the modem using the client credentials.
//
// Returns the login response if the login was successful, or an nil map
// and an error on a login failure.
func (c *MotoClient) Login() (map[string]string, error) {
	data := map[string]string{
		"Action":        "request",
		"Captcha":       "",
		"PrivateLogin":  "LoginPassword",
		"Username":      c.Username,
		"LoginPassword": "",
	}

	resp, err := c.do("Login", data)
	if err != nil {
		return nil, err
	}

	val, ok := resp["LoginResult"]
	if !ok || val == "FAILED" {
		return nil, fmt.Errorf("login failed")
	}

	publicKey := resp["PublicKey"]
	challenge := resp["Challenge"]

	c.SetPrivateKey(md5Sum(fmt.Sprintf("%s%s", publicKey, c.Password), challenge))
	c.SetUID(resp["Cookie"])

	pkey, err := c.GetPrivateKey()
	if err != nil {
		return nil, err
	}
	data["Action"] = "login"
	data["LoginPassword"] = md5Sum(pkey, challenge)
	resp, err = c.do("Login", data)
	if err != nil {
		return nil, err
	}

	if val, ok = resp["LoginResult"]; !ok || val == "FAILED" {
		return nil, fmt.Errorf("login failed")
	}

	return resp, nil
}

// Returns a list of DownstreamChannel objects, or nil on an error.
func (c *MotoClient) GetDownstreamChannels() ([]*DownstreamChannel, error) {
	resp, err := c.do("GetMotoStatusDownstreamChannelInfo", nil)
	if err != nil {
		return nil, err
	}
	data := resp["MotoConnDownstreamChannel"]
	level.Debug(c.Logger).Log("msg", "got downstream channels", "data", data)
	return NewDownstreamChannelsFromResponse(data)
}

// Returns a list of UpstreamChannel objects, or nil on an error.
func (c *MotoClient) GetUpstreamChannels() ([]*UpstreamChannel, error) {
	resp, err := c.do("GetMotoStatusUpstreamChannelInfo", nil)
	if err != nil {
		return nil, err
	}
	data := resp["MotoConnUpstreamChannel"]
	level.Debug(c.Logger).Log("msg", "got upstream channels", "data", data)
	return NewUpstreamChannelsFromResponse(data)
}
