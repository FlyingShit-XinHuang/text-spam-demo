package main

import (
	"net/http"
	"time"
	"log"
	"crypto/rand"
	"math/big"
	"encoding/base64"
	"bytes"
	"crypto/hmac"
	"fmt"
	"io/ioutil"
	"strconv"
	"crypto/sha1"
	//"crypto/sha256"
	"net/url"
)

func main() {
	NewAntiSpamClient("", "").
		Request("mid1", "user1", "前方路口，交通拥堵", "法lun功")
}

func qcloudDemo(msg string) {
}

func genNounce() string {
	i, err := rand.Int(rand.Reader, big.NewInt(100000))
	if nil != err {
		panic(err)
	}
	return i.String()
}

var tlvType = []byte{0, 0, 0, 1}

func tlvEncode(msgs ...string) string {
	buf := bytes.NewBuffer(nil)
	for _, msg := range msgs {
		raw := []byte(msg)
		length := len(raw)
		// set type
		buf.Write(tlvType)
		// set length
		buf.WriteByte(byte(length & 0xff000000 >> 24))
		buf.WriteByte(byte(length & 0x00ff0000 >> 16))
		buf.WriteByte(byte(length & 0x0000ff00 >> 8))
		buf.WriteByte(byte(length & 0x000000ff >> 0))
		// set content
		buf.Write(raw)
	}
	log.Println(buf.Bytes())

	// base64 encode
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

const (
	scheme = "https"
	antiSpamUrl = "csec.api.qcloud.com/v2/index.php"
	antiSpamAction = "UgcAntiSpam"
	antiSpamRegion = "bj"
	//signMethod = "HmacSHA1"
	antiSpamAccType = "0"
)

var sortedKeys = []string{
	// common parameters
	"Action",
	"Nonce",
	"Region",
	"SecretId",
	//"SignatureMethod",
	"Timestamp",

	// api parameters
	"accountType",
	"messageId",
	"messageStruct",
	"postIp",
	"uid",
}

type antiSpamClient struct {
	httpMethod string
	url string
	secretId string
	secretKey string
	values url.Values
}

type formValues map[string]string

func (f formValues) Set(key, value string) {
	f[key] = value
}

func (f formValues) Get(key string) string {
	return f[key]
}

func (f formValues) Reader() *bytes.Buffer {
	buf := bytes.NewBufferString("")
	for key, value := range f {
		if 0 != buf.Len() {
			buf.WriteByte('&')
		}
		buf.WriteString(key + "=" + value)
	}
	return buf
}

func NewAntiSpamClient(secretId, secretKey string) (*antiSpamClient) {
	vals := url.Values{}
	vals.Set("Action", antiSpamAction)
	vals.Set("Region", antiSpamRegion)
	vals.Set("SecretId", secretId)
	//vals.Set("SignatureMethod", signMethod)
	return &antiSpamClient{
		httpMethod: http.MethodPost,
		url: antiSpamUrl,
		secretId: secretId,
		secretKey: secretKey,
		values: vals,
	}
}

func (c *antiSpamClient) Request(msgId, uid string, msg ...string) {
	c.values.Set("Nonce", genNounce())
	c.values.Set("Timestamp", strconv.FormatInt(time.Now().UTC().Unix(), 10))
	c.values.Set("messageStruct", tlvEncode(msg...))
	c.values.Set("accountType", antiSpamAccType)
	c.values.Set("messageId", msgId)
	c.values.Set("postIp", "127.0.0.1")
	c.values.Set("uid", uid)

	//log.Println(c.sign())
	c.values.Set("Signature", c.sign())

	log.Println(c.values.Encode())

	//u, _ := url.Parse(scheme + "://" + c.url)
	//u.RawQuery = c.values.Encode()
	//log.Println(u.String())
	//resp, err := http.Get(u.String())
	resp, err := http.PostForm(scheme + "://" + c.url, c.values)
		//http.Post(c.url, "application/x-www-form-urlencoded", c.values.Reader())
	if nil != err {
		log.Fatalf("request error: %#v\n", err)
	}

	defer resp.Body.Close()

	result, _ := ioutil.ReadAll(resp.Body)
	log.Println(resp.StatusCode)
	log.Println(string(result))
}

func (c *antiSpamClient) sign() string {
	buf := bytes.NewBufferString(c.httpMethod)
	buf.WriteString(c.url)
	c.writeParams(buf)
	log.Println(buf.String())

	h := hmac.New(sha1.New, []byte(c.secretKey))
	h.Write(buf.Bytes())
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (c *antiSpamClient) writeParams(buf *bytes.Buffer) {
	sep := "?"
	for i, key := range sortedKeys {
		if 0 != i {
			sep = "&"
		}
		buf.WriteString(fmt.Sprintf("%s%s=%s", sep, key, c.values.Get(key)))
	}
}