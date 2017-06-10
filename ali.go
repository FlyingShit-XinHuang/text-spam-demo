package main

import (
	"net/http"
	"log"
	"time"
	"crypto/rand"
	"encoding/hex"
	"crypto/hmac"
	"crypto/sha1"
	"bytes"
	"encoding/base64"
	"crypto/md5"
	"encoding/json"
	"io/ioutil"
)

func main() {
	aliDemo()

}

const (
	aliVerionHeader      = "x-acs-version"
	aliSignNonceHeader   = "x-acs-signature-nonce"
	aliSignVersionHeader = "x-acs-signature-version"
	aliSignMethodHeader  = "x-acs-signature-method"

	aliVer      = "2017-01-12"
	aliSignVer  = "1.0"
	aliSignMeth = "HMAC-SHA1"
)

func aliDemo() {
	secretId := ""
	secretKey := ""
	path := "/green/text/scan"

	body := genAliBody()
	req, err := http.NewRequest(http.MethodPost, "http://green.cn-shanghai.aliyuncs.com" + path, bytes.NewReader(body))
	if nil != err {
		log.Fatalf("init request error: %#v\n", err)
	}

	date := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	nonce := genAliNounce()
	//log.Println(string(body))
	signed := md5.Sum(body)
	bodySign := base64.StdEncoding.EncodeToString(signed[:])

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-MD5", bodySign)
	req.Header.Set("Date", date)
	req.Header.Set(aliSignMethodHeader, aliSignMeth)
	req.Header.Set(aliSignNonceHeader, nonce)
	req.Header.Set(aliSignVersionHeader, aliSignVer)
	req.Header.Set(aliVerionHeader, aliVer)
	req.Header.Set("Authorization",
		"acs " + secretId + ":" + genAliSign(bodySign, date, aliSignMeth, nonce, aliSignVer, aliVer, path, []byte(secretKey)))

	//log.Println(genAliSign(bodySign, date, aliSignMeth, nonce, aliSignVer, aliVer, path, []byte("69X6ySTHQZdqkXsuDndcL2YfIej9or")))
	resp, err := http.DefaultClient.Do(req)
	if nil != err {
		log.Fatal("request error: %#v\n", err)
	}

	defer resp.Body.Close()
	log.Println(resp.StatusCode)

	result, _ := ioutil.ReadAll(resp.Body)
	log.Println(string(result))
}

func genAliSign(bodySign, date, sMethod, sNonce, sVersion, version, path string, key []byte) string {
	buf := bytes.NewBufferString("POST\n")
	buf.WriteString("application/json\n")
	buf.WriteString(bodySign + "\n")
	buf.WriteString("application/json\n")
	buf.WriteString(date + "\n")
	buf.WriteString(aliSignMethodHeader + ":" + sMethod + "\n")
	buf.WriteString(aliSignNonceHeader + ":" + sNonce + "\n")
	buf.WriteString(aliSignVersionHeader + ":" + sVersion + "\n")
	buf.WriteString(aliVerionHeader + ":" + version + "\n")
	buf.WriteString(path)

	h := hmac.New(sha1.New, key)
	h.Write(buf.Bytes())
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func genAliBody() []byte {
	req := aliTextScanReq{
		Scenes: []string{"keyword"},
	}
	req.Tasks = append(req.Tasks, aliTextScanTask{
		DataId: "1",
		Content: "前方路口，交通拥堵",
	}, aliTextScanTask{
		DataId: "2",
		Content: "还有没有王法论功请赏",
	})
	data, err := json.Marshal(req)
	if nil != err {
		log.Fatal("encode json error: %#v\n", err)
	}
	return data
}

func genAliNounce() string {
	r := make([]byte, 10)

	if _, err := rand.Read(r); nil != err {
		panic(err)
	}
	return hex.EncodeToString(r)
}

type aliTextScanReq struct {
	Scenes []string `json:"scenes"`
	Tasks []aliTextScanTask `json:"tasks"`
}

type aliTextScanTask struct {
	Content string `json:"content"`
	DataId string `json:"dataId"`
}
