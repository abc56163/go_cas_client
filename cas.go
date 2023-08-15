package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/fernet/fernet-go"
)


type CasClient struct {
	CasURL       string
	SecretKey    []*fernet.Key
	CookieName   string
	LoginURL     string
	CookieMaxAge time.Duration
	CallBackUrl  string
}

// 解析验证票据返回值
type CasValue struct {
	XMLName xml.Name `xml:"serviceResponse"`
	Success struct {
		User       string `xml:"user"`
		Attributes struct {
			Gender      string `xml:"gender"`
			Accounttype string `xml:"accounttype"`
			Mobile      string `xml:"mobile"`
			Leaders     string `xml:"leaders"`
			Employid    string `xml:"employid"`
			Cityid      string `xml:"cityid"`
			Realname    string `xml:"realname"`
			Org_id      string `xml:"org_id"`
			Location    string `xml:"location"`
			Tenantcode  string `xml:"tenantcode"`
			Email       string `xml:"email"`
		} `xml:"Attributes"`
	} `xml:"authenticationSuccess"`
}


// cas客户端生成器
func NewClient(casUrl string) *CasClient {
	key := generateFernetKey()
	base64key := base64.StdEncoding.EncodeToString(key)
	k := fernet.MustDecodeKeys(string(base64key))
	return &CasClient{
		CasURL:       casUrl,
		SecretKey:    k,
		CookieName:   "session",
		CookieMaxAge: 108000,
		CallBackUrl:  "/login",
	}
}

// 生成加密的随机字串，FernetKey要32个字节
func generateFernetKey() []byte {
	// 生成32字节的随机密钥
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic("Failed to generate Fernet key")
	}
	return key
}
// 将用户重定向到CAS登录页面
func (c *CasClient) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	requestUrl := c.getUrl(r)
	loginURL := fmt.Sprintf("%s/login?service=%s", c.CasURL, url.QueryEscape(requestUrl))
	http.Redirect(w, r, loginURL, http.StatusFound)
	return
}
// 退出登录
func (c *CasClient) redirectToLogOut(w http.ResponseWriter, r *http.Request) {
	requestUrl := c.getUrl(r)
	logOutURL := fmt.Sprintf("%s/logout?service=%s", c.CasURL, url.QueryEscape(requestUrl))
	http.Redirect(w, r, logOutURL, http.StatusFound)
	return
}

// 获取访问的地址，登录成功后跳转到改地址而不是首页
/*
	如果使用的是nginx反向代理，需要传递正式的host建议按照如下方法写
	proxy_set_header Host $http_host;
	proxy_set_header X-Real-IP $remote_addr;
	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	proxy_set_header X-Forwarded-Proto $scheme;
*/
func (c *CasClient) getUrl(r *http.Request) string {
	url := r.Host
	urlPath := r.URL.Path
	if urlPath != "/" {
		url = url + urlPath
	}
	// 获取请求的模式，判断是http还是https
	mode := "http"
	if r.TLS != nil {
		mode = "https"
	}
	return fmt.Sprintf("%s://%s", mode, url)
}

// encryptData
func (c *CasClient) encryptData(data []byte) (string, error) {
	tok, err := fernet.EncryptAndSign(data, c.SecretKey[0])
	return string(tok), err
}

// decryptData
func (c *CasClient) decryptData(encryptedData []byte) []byte {
	data := fernet.VerifyAndDecrypt(encryptedData, c.CookieMaxAge*time.Second, c.SecretKey)
	return data
}

// 根据session获取浏览器储存的cookie值
func (c *CasClient) GetSessionValue(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	cookie, err := r.Cookie(c.CookieName)
	if err != nil {
		return nil, err
	}
	cookieValue := c.decryptData([]byte(cookie.Value))
	if len(cookieValue) == 0 {
		return nil, errors.New("Session parsing failed")
	}
	return cookieValue, err
}

// 设置浏览器 cookie的session
func (c *CasClient) setSessionValue(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:    c.CookieName,
		Value:   value,
		Expires: time.Now().Add(c.CookieMaxAge * time.Second),
	})
}

// 获取url后面的ticket
func (c *CasClient) getTicket(w http.ResponseWriter, r *http.Request) string {
	ticket := r.URL.Query().Get("ticket")
	if ticket == "" {
		c.redirectToLogin(w, r)
		return ""
	}
	return ticket
}

//验证票据 ValidateServiceTicket 并解析数据，然后设置浏览器cookie
func (c *CasClient) CasValidateServiceTicket(w http.ResponseWriter, r *http.Request, ticket string) error {
	callBackUrl := c.getUrl(r)
	validateURL := fmt.Sprintf("%s/serviceValidate?ticket=%s&service=%s", c.CasURL, ticket, callBackUrl)
	resp, err := http.Get(validateURL)
	if err != nil {
		return errors.New("Failed to validate ticket," + err.Error())
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	// 解析CAS服务器的XML响应
	response := CasValue{}
	err = xml.Unmarshal(b, &response)
	if err != nil {
		return err
	}
	// 根据XML响应中的结果判断票据是否有效
	if response.Success.User != "" {
		respByte, _ := json.Marshal(response)
		encyptData, _ := c.encryptData(respByte)
		c.setSessionValue(w, r, encyptData)
		return nil
	}
	return fmt.Errorf("CAS ticket validation failed")
}

// 判断是否认证
func (c *CasClient) IsAuthentication(w http.ResponseWriter, r *http.Request) {
	_, err := c.GetSessionValue(w, r)
	if err != nil {
		ticket := r.URL.Query().Get("ticket")
		if ticket != "" {
			err := c.CasValidateServiceTicket(w, r, ticket)
			if err != nil {
				c.redirectToLogin(w, r)
				return
			}
		}
		c.redirectToLogin(w, r)
		return
	}
	return
}

// 退出登录
func (c *CasClient) clearSession(w http.ResponseWriter, r *http.Request) {
	// 设置过期时间使Cookie失效

	http.SetCookie(w, &http.Cookie{
		Name:    c.CookieName,
		Value:   "",
		Expires: time.Now().Add(-1),
	})
	c.redirectToLogOut(w, r)
}
