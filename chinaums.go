package config

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"easyebid/common"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/spf13/cast"
	"github.com/tal-tech/go-zero/core/logx"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	AppId    = "10037e6f6823b20801682b6a5e5a0006"
	AppKeys  = "1c4e3b16066244ae9b236a09e5b312e8"
	MId      = "898340149000005"
	TId      = "88880001"
	InstMId  = "QRPAYDEFAULT"
	MsgSrcId = "1017"
	MD5Key   = "impARTxrQcfwmRijpDNCw6hPxaWCddKEpYxjaKXDhCaTCXJ6"
	PayUrl   = "https://test-api-open.chinaums.com/v1/netpay/"
	//
	// APP
	AppAppId   = "10037e6f66f2d0f901672aa27d690006"
	AppAppKeys = "47ace12ae3b348fe93ab46cee97c6fde"
	AppMId     = "898201612345678"
	AppTId     = "88880001"
	AppMD5Key  = "impARTxrQcfwmRijpDNCw6hPxaWCddKEpYxjaKXDhCaTCXJ6"
	AppInstMId = "APPDEFAULT"

	// 小程序支付
	MiniAppInstMId = "MINIDEFAULT"
	WXAppId = "wxe0ed442406921d09"
	AppSecret = "670918d7c92c6eede15f2a543ab1c998"
	AppletMid = "898201612345678"

	// 以下为提现系统参数
	SysId = "10003"
	// 外部平台私钥
	PrivateKeys = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAAbXA7tnnMuWV6WO1bKEKGyKZRFcRCGDW+UfGFZdx0MEm6+fKTNGTsalEFwFPK36YtQFXcN0FciGmQp1wGts4IqLaEzk9az5UcxIfR00JxpNsTYSZb82ZMpj52WF0FHtyj7qE+K3k/FcKCcEHQ3Soa9LL/GQpyVO0yhxeV5tiRfnHoJxxCRHp3jM//VnlCd6koTwPNPFKsf8Vf+dtGA3/BZPFoHvFP0+vfLmEi2TIHO1f1CZDg67TiC/Kkusl0XBiUAXhjAz1SleNQzKHtUVPbVluBtG8ydk8kcLpqDDST6WPnHg5NgHt9qXp0vOLO7ABkQz+dGCXKm+tWXHnRjj1AgMBAAECggEAMm7AjMKwHZgy0aOR+w9jZUInXlai/+hRd2XWwmLdepm4gj6ojWyMB908dpQMVf04rWetyIfupgWKbR9GNzH2rtH6MImoGUfYAVqQQgL6azzrcCEUWTESsdCmecntXQ4cNsUl2tNu6ZyWSB6zwvKm664Wmlna/VbSU8RamzUrrS362gxNFdcEyvCstlnNx1aC5VCRFHm6uBO2uFSYR4dh4e0KpEmYsPT41k93Z4KQHFTCwcvuQu+or5WKL44hKYHyXoZbWiZhfvBRXBVDT7TLmObkeQXAr/Uu1SO5AkblYqG0dyYVy1ea2xANjt8Mw+OP4kRu8IFikALwWp4iYdyAaQKBgQD5mrsx6KrRHbtpBZzHBcEL+/tttA8YAskH2NlkEcGDPcwwULdEYRUUEvX5J+9sTwZHLnE6O9YKI0UtbEBLmDGDfoHy9OM0NCHEaxmZJvmizzfGGc4u/+EtrNCZh1nXUvz1cPip6tywpuHuIgcdAczm0kD9vMWcKHWJSZv+gdClpwKBgQDE7StEIc/c4/fYjIzUaMh6NHqGGB/SpqpfyKHdNZG1xhacN3zY44fO4X8U93uV+thhY3a66TjvvfC2kQAidWWwn4DzmOgWCSPPtuYuI5vouqW/HL8rLKf3hV2rGCC6fz9PDgjy1tl6ZxI10YsA0VjWuHQ9OcQjBl/ypoGfTCJ4AwKBgQCvMhwSe+zpuqTAol/YkgFeGA/ygF/XypywFVUBGDVrmQSpJP590GarIGPl7lHvA8i0TbTL2xPxKbB0oXa/mKOoWDN+BMU07yKEa2gcR28RB8FuGs7NzmyPUq1YFdjJekZzQEhJe8BLfdc2/ktf4NOhcBKOBuHtKbjWFASaLyP0IQKBgHjRSYozdGQBOT4SfRSUdOsE52b9xghnWIALh8M/6nWrYpPVNzOZ5Oh4UI98hsYtcDPP4jgqflQYJGbd70c0337NXUAWv81FLkNx4ybLkgvm92mZKXBDpYmmuSEPXIUPLLhD1Bmo1yTRt8ptFOsbhXW3FRm7JyqV7qfgoAYrn7ohAoGAT2YHHABe8UHfo8ZnLKjjC3FfUcrGd87LTB8EbADVb+Vuak7/8/FTGRDGxygeH3/haB86Dv1nRQJ2Jp1fS9HrWfX/cart1H6Ef/FKT6Td3aCZAwM6kTLWkDepX+2qWW3pnKytrnp1rHFu9XIR+iFlG2hFOg+ppzUKfX3L3A57xDU="

	// 外部平台PKCS1私钥（银联商务提供的PKCS8格式需转为PKCS1格式）
	PrivateKeyPkcs1 = "MIIEowIBAAKCAQEAwAG1wO7Z5zLlleljtWyhChsimURXEQhg1vlHxhWXcdDBJuvnykzRk7GpRBcBTyt+mLUBV3DdBXIhpkKdcBrbOCKi2hM5PWs+VHMSH0dNCcaTbE2EmW/NmTKY+dlhdBR7co+6hPit5PxXCgnBB0N0qGvSy/xkKclTtMocXlebYkX5x6CccQkR6d4zP/1Z5QnepKE8DzTxSrH/FX/nbRgN/wWTxaB7xT9Pr3y5hItkyBztX9QmQ4Ou04gvypLrJdFwYlAF4YwM9UpXjUMyh7VFT21ZbgbRvMnZPJHC6agw0k+lj5x4OTYB7fal6dLzizuwAZEM/nRglypvrVlx50Y49QIDAQABAoIBADJuwIzCsB2YMtGjkfsPY2VCJ15Wov/oUXdl1sJi3XqZuII+qI1sjAfdPHaUDFX9OK1nrciH7qYFim0fRjcx9q7R+jCJqBlH2AFakEIC+ms863AhFFkxErHQpnnJ7V0OHDbFJdrTbumclkges8LypuuuFppZ2v1W0lPEWps1K60t+toMTRXXBMrwrLZZzcdWguVQkRR5urgTtrhUmEeHYeHtCqRJmLD0+NZPd2eCkBxUwsHL7kLvqK+Vii+OISmB8l6GW1omYX7wUVwVQ0+0y5jm5HkFwK/1LtUjuQJG5WKhtHcmFctXmtsQDY7fDMPjj+JEbvCBYpAC8FqeImHcgGkCgYEA+Zq7Meiq0R27aQWcxwXBC/v7bbQPGALJB9jZZBHBgz3MMFC3RGEVFBL1+SfvbE8GRy5xOjvWCiNFLWxAS5gxg36B8vTjNDQhxGsZmSb5os83xhnOLv/hLazQmYdZ11L89XD4qercsKbh7iIHHQHM5tJA/bzFnCh1iUmb/oHQpacCgYEAxO0rRCHP3OP32IyM1GjIejR6hhgf0qaqX8ih3TWRtcYWnDd82OOHzuF/FPd7lfrYYWN2uuk4773wtpEAInVlsJ+A85joFgkjz7bmLiOb6Lqlvxy/Kyyn94Vdqxggun8/Tw4I8tbZemcSNdGLANFY1rh0PTnEIwZf8qaBn0wieAMCgYEArzIcEnvs6bqkwKJf2JIBXhgP8oBf18qcsBVVARg1a5kEqST+fdBmqyBj5e5R7wPItE20y9sT8SmwdKF2v5ijqFgzfgTFNO8ihGtoHEdvEQfBbhrOzc5sj1KtWBXYyXpGc0BISXvAS33XNv5LX+DToXASjgbh7Sm41hQEmi8j9CECgYB40UmKM3RkATk+En0UlHTrBOdm/cYIZ1iAC4fDP+p1q2KT1TczmeToeFCPfIbGLXAzz+I4Kn5UGCRm3e9HNN9+zV1AFr/NRS5DceMmy5IL5vdpmSlwQ6WJprkhD1yFDyy4Q9QZqNck0bfKbRTrG4V1txUZuycqle6n4KAGK5+6IQKBgE9mBxwAXvFB36PGZyyo4wtxX1HKxnfOy0wfBGwA1W/lbmpO//PxUxkQxscoHh9/4WgfOg79Z0UCdiadX0vR61n1/3Gq7dR+hH/xSk+k3d2gmQMDOpEy1pA3qV/tqllt6Zysra56daxxbvVyEfohZRtoRToPqac1Cn19y9wOe8Q1"

	// 银商系统公钥
	PublicKeys = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu13Ykr8Q4ACqnYMfLL5kgV2JsUC7TQEeWR70Zpulqq6JeujD6dCupnYnGhnMmePasgBZT0rIKGvoUEe5tMS1sfYo6dMqaAwcVfe4XOQaPSQs10XDSMB689+ImZmhECEBJkbKs7K+BBJXBOZGkgHBZsd4pn3vlF4E2yPTrfrcn9OEXZAKrUb/jZm6suzHoXSljqtHWwT7OwQoIX+Q/27gYA6PuGpFFmr4Xtc4a/AqIHeCC4TinbgboD8HqfL0ZoC4NG6Xm2KJ9wK66MbS7sYRiK+7pctZkZLxIJ47Ro5Psuxs4owTdtY7b1aHun9GoUT6Wm4mRO0asvBv0XKn05qn9wIDAQAB"

	// 提现接口链接
	WithdrawUrl = "https://mobl-test.chinaums.com/uisouterfront/"
)

// GetOpenBodySign 请求参数加密
func GetOpenBodySign(payType, queryType, apiUrl string, content []byte) (string, error) {
	client := &http.Client{}
	appId := AppId
	appKeys := AppKeys
	//// app
	//if payType == "2" {
	//	appId = AppAppId
	//	appKeys = AppAppKeys
	//}
	timestamp := time.Now().Format("20060102150405")
	nonce := common.MD5V(cast.ToString(time.Now().UnixNano()))
	//fmt.Println(string(content), 123321)
	//需要先把内容加密转成16进制
	hashEr := sha256.New()
	hashEr.Write(content)
	newContentHash := hex.EncodeToString(hashEr.Sum(nil))
	//fmt.Println(newContentHash)
	m := hmac.New(sha256.New, []byte(appKeys))
	m.Write([]byte(appId + timestamp + nonce + newContentHash))
	//fmt.Println(appId+timestamp+nonce+newContentHash, 1)
	//signature := base64.URLEncoding.EncodeToString(m.Sum(nil))
	signature := base64.StdEncoding.EncodeToString(m.Sum(nil))
	//fmt.Println(signature, 2)
	authorization := "OPEN-BODY-SIG AppId=\"" + appId + "\",Timestamp=\"" + timestamp + "\",Nonce=\"" + nonce + "\",Signature=\"" + signature + "\""
	//fmt.Println(authorization, 3)
	req, err := http.NewRequest(queryType, PayUrl+apiUrl, bytes.NewReader(content))
	if err != nil {
		logx.Error(err)
		fmt.Println(err)
	}
	//fmt.Println(req, 4)
	//req, err := http.NewRequest("POST", "https://qr-test2.chinaums.com/netpay-route-server/api/", strings.NewReader(string(data)))
	//if err != nil {
	//	panic(err)
	//}
	req.Header.Set("Authorization", authorization)
	//req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	//req.Header.Set("Content-Length", string(len(data)))
	resp, err := client.Do(req)
	defer resp.Body.Close()
	response, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println(string(response), 222222)
	return string(response), nil
}

//GetDecodeSign 支付通知加密
func GetDecodeSign(req *http.Request) (string, bool) {
	appKeys := MD5Key
	//// app
	//if req.Form.Get("instMid") == "APPDEFAULT" {
	//	appKeys = AppMD5Key
	//}

	if req.ParseForm() != nil {
		return "", false
	}
	//
	var form map[string][]string = req.Form
	bm := ""
	for k, v := range form {
		if k == "sign" || v[0] == "" {
			continue
		}
		bm += k + "=" + v[0] + "&"
	}
	newStr := strings.TrimRight(bm, "&")
	newUrls := strings.Split(newStr, "&")
	sort.Strings(newUrls)
	str := ""
	for _, v := range newUrls {
		str += v + "&"
	}
	newSign := strings.TrimRight(str, "&") + appKeys
	h := sha256.New()
	h.Write([]byte(newSign))
	sum := h.Sum(nil)
	newContentHash := hex.EncodeToString(sum)
	//fmt.Println(sum,223344,newSign, 00000, newContentHash, 11111, req.Form.Get("sign"))
	if strings.EqualFold(newContentHash, req.Form.Get("sign")) == false {
		return str, false
	}
	return str, true
}

//WithDrawSign 提现加密算法
func WithDrawSign(data map[string]string) (string, bool) {
	bm := ""
	for k, v := range data {
		if k == "sign" || v == "" {
			continue
		}
		bm += k + "=" + v + "&"
	}
	newStr := strings.TrimRight(bm, "&")
	newUrls := strings.Split(newStr, "&")
	sort.Strings(newUrls)
	str := ""
	for _, v := range newUrls {
		str += v + "&"
	}
	newSign := strings.TrimRight(str, "&")
	return newSign, true
}

//key是否具有头尾换行不交由程序判断
//ifPublic true 为公钥， false为私钥
func formatKey(key string, ifPublic bool) string {
	if ifPublic {
		var publicHeader = "\n-----BEGIN PUBLIC KEY-----\n"
		var publicTail = "-----END PUBLIC KEY-----\n"
		var temp string
		split(key, &temp)
		return publicHeader + temp + publicTail
	} else {
		var publicHeader = "\n-----BEGIN RSA PRIVATE KEY-----\n"
		var publicTail = "-----END RSA PRIVATE KEY-----\n"
		var temp string
		split(key, &temp)
		return publicHeader + temp + publicTail
	}
}

func split(key string, temp *string) {
	if len(key) <= 64 {
		*temp = *temp + key + "\n"
	}
	for i := 0; i < len(key); i++ {
		if (i+1)%64 == 0 {
			*temp = *temp + key[:i+1] + "\n"
			key = key[i+1:]
			split(key, temp)
			break
		}
	}
}

// privateRsaEncrypt 私钥加签
func PrivateRsaEncrypt(newSign []byte) string {
	//fmt.Println(string(newSign))
	h := sha256.New()
	h.Write(newSign)
	sum := h.Sum(nil)
	//fmt.Println(newContentHash)

	pri, _ := GetPrivateRsa()
	signature, _ := rsa.SignPKCS1v15(rand.Reader, pri, crypto.SHA256, sum)
	return base64.RawURLEncoding.EncodeToString(signature)
	//return base64.StdEncoding.EncodeToString(signature)
	//return string(signature)
}

// 私钥解密
func PrivateDecrypt(encrypted string) (string, error) {
	pri, _ := GetPrivateRsa()
	partLen := pri.N.BitLen() / 8
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	chunks := splitPub([]byte(raw), partLen)
	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, pri, chunk)
		fmt.Println(decrypted,12,err)
		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}
	return buffer.String(), err
}

// PublicRsaEncrypt 银联公钥加密
func PublicRsaEncrypt(sign string) string {
	p, _ := GetPublicRsa()
	pubLen := p.N.BitLen()/8 - 11
	chunks := splitPub([]byte(sign), pubLen)
	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bytes, _ := rsa.EncryptPKCS1v15(rand.Reader, p, chunk)
		buffer.Write(bytes)
	}
	return hex.EncodeToString(buffer.Bytes())
}

// 数据验签
func Verify(data string, sign string) error {
	h := sha256.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	decodedSign, err := base64.RawURLEncoding.DecodeString(sign)
	if err != nil {
		return err
	}
	pub, _ := GetPublicRsa()
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, decodedSign)
}

func HttpRequest(msgType string, data io.ReadCloser) (string, error) {
	clients := &http.Client{}
	req, err := http.NewRequest("POST", WithdrawUrl+msgType, data)
	if err != nil {
		logx.Error(err)
		fmt.Println(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	//req.Header.Set("Content-Length", string(len(data)))
	resp, err := clients.Do(req)
	defer resp.Body.Close()
	response, _ := ioutil.ReadAll(resp.Body)
	return string(response), nil
}

func splitPub(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}

// GetPublicRsa 获取公钥签名
func GetPublicRsa() (*rsa.PublicKey, error) {
	newPublicKey := formatKey(PublicKeys, true)
	publicKey, _ := pem.Decode([]byte(newPublicKey))
	publicSign, _ := x509.ParsePKIXPublicKey(publicKey.Bytes)
	pub := publicSign.(*rsa.PublicKey)
	return pub, nil
}

// GetPrivateRsa 获取私钥签名
func GetPrivateRsa() (*rsa.PrivateKey, error) {
	//newPrivateKey := formatKey(PrivateKeys, false)
	newPrivateKey := strings.Trim(PrivateKeys, "\n")
	if !strings.HasPrefix(newPrivateKey, "-----BEGIN RSA PRIVATE KEY-----") {
		newPrivateKey = fmt.Sprintf("%s\n%s\n%s", "-----BEGIN RSA PRIVATE KEY-----", newPrivateKey, "-----END RSA PRIVATE KEY-----")
	}

	priKey, _ := pem.Decode([]byte(newPrivateKey))
	encryptedBytes, _ := x509.ParsePKCS8PrivateKey(priKey.Bytes)
	pri := encryptedBytes.(*rsa.PrivateKey)
	return pri, nil
}
