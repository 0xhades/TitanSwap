package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Pallinder/go-randomdata"
	"github.com/google/uuid"
)

type API struct {
	USERAGENT    string
	VERSION      string
	KeyVersion   string
	KEY          string
	CAPABILITIES string
}

type HttpResponse struct {
	Err                 error
	ResStatus           int
	Req                 *http.Request
	Res                 *http.Response
	Body                string
	Headers             http.Header
	Cookies             []*http.Cookie
	RequestSizeByBytes  float64
	ResponseSizeByBytes float64
}

type Secret struct {
	version string
	key     string
}

func randDevice(version string) string {

	dpi := []string{
		"480", "320", "640", "515", "120", "160", "240", "800",
	}
	manufacturers := []string{
		"HUAWEI", "Xiaomi", "samsung", "OnePlus", "LGE/lge", "ZTE", "HTC",
		"LENOVO", "MOTOROLA", "NOKIA", "OPPO", "SONY", "VIVO", "LAVA",
	}

	randResolution := randomdata.Number(2, 9) * 180
	lowerResolution := randResolution - 180

	androidVersion := randomdata.Number(18, 25)
	androidRelease := fmt.Sprintf("%d.%d", randomdata.Number(1, 7), randomdata.Number(0, 7))
	if randomdata.Boolean() {
		androidRelease = fmt.Sprintf("%d.%d.%d", randomdata.Number(1, 7), randomdata.Number(0, 7), randomdata.Number(1, 7))
	}
	_dpi := dpi[randomdata.Number(0, len(dpi))]
	resolution := fmt.Sprintf("%dx%d", lowerResolution, randResolution)
	manufacturer := manufacturers[randomdata.Number(0, len(manufacturers))]
	device := fmt.Sprintf("%s-%s", manufacturers[randomdata.Number(0, len(manufacturers))], randomdata.RandStringRunes(5))
	model := randomdata.RandStringRunes(4)
	cpu := fmt.Sprintf("%s%d", randomdata.RandStringRunes(2), randomdata.Number(1000, 9999))

	UserAgentBase := "Instagram %s Android (%d/%s; %s; %s; %s; %s; %s; %s; en_US)"
	return fmt.Sprintf(UserAgentBase, version, androidVersion, androidRelease, _dpi, resolution, manufacturer, device, model, cpu)

}

func GetAPI() API { // random choise

	var version string
	var key string

	version = fmt.Sprintf("%d.%d.%d", randomdata.Number(3, 138), randomdata.Number(5, 10), randomdata.Number(0, 10))
	if randomdata.Boolean() {
		version = fmt.Sprintf("%d.%d.%d", randomdata.Number(4, 138), randomdata.Number(0, 10), randomdata.Number(0, 10))
	}
	key = "SIGNATURE"

	USERAGENT := randDevice(version)
	IG_VERSION := version
	IG_SIG_KEY := key
	SIG_KEY_VERSION := "4"
	if randomdata.Boolean() {
		SIG_KEY_VERSION = "5"
	}
	X_IG_Capabilities := "3brTvw=="
	if randomdata.Boolean() {
		X_IG_Capabilities = fmt.Sprintf("%s==", randomdata.RandStringRunes(6))
	}

	_API := API{VERSION: IG_VERSION, KEY: IG_SIG_KEY, KeyVersion: SIG_KEY_VERSION, CAPABILITIES: X_IG_Capabilities, USERAGENT: USERAGENT}

	return _API
}

func MakeHttpResponse(Response *http.Response, Request *http.Request, Error error, RequestSizeByBytes float64, ResponseSizeByBytes float64) HttpResponse {

	var res = ""
	var StatusCode = 0
	var Headers http.Header = nil
	var cookies []*http.Cookie = nil
	var err error

	if Error != nil {
		err = Error
	}
	if Response != nil {
		cookies = Response.Cookies()
		var reader io.ReadCloser
		switch Response.Header.Get("Content-Encoding") {
		case "gzip":
			reader, _ = gzip.NewReader(Response.Body)
			defer reader.Close()
		default:
			reader = Response.Body
		}
		body, _ := ioutil.ReadAll(reader)
		res = string(body)

		if Response.Header != nil {
			Headers = Response.Header
		}

		if Response.StatusCode != 0 {
			StatusCode = Response.StatusCode
		}
	}

	return HttpResponse{ResStatus: StatusCode, Res: Response, ResponseSizeByBytes: ResponseSizeByBytes, Req: Request, RequestSizeByBytes: RequestSizeByBytes, Body: res, Headers: Headers, Cookies: cookies, Err: err}
}

func instRequest(iurl string, signedbody map[string]string, payload string,
	Headers map[string]string, api API, proxy string,
	cookie []*http.Cookie, usecookies bool, MiliTimeout int) HttpResponse {

	_url := iurl

	if ((!strings.Contains(_url, "https")) || (!strings.Contains(_url, "http"))) && _url[0] != '/' {
		_url = "https://i.instagram.com/api/v1/" + _url
	} else if ((!strings.Contains(_url, "https")) || (!strings.Contains(_url, "http"))) && _url[0] == '/' {
		_url = "https://i.instagram.com/api/v1" + _url
	}

	_api := API{}
	if api == (API{}) {
		_api = GetAPI()
	} else {
		_api = api
	}

	_payload := ""
	if signedbody != nil {
		_data, _ := json.Marshal(signedbody)
		_json := string(_data)
		_signed := fmt.Sprintf("SIGNATURE.%s", _json)
		_payload = "ig_sig_key_version=" + _api.KeyVersion + "&signed_body=" + _signed
	} else if payload != "" {
		_payload = payload
	}

	var req *http.Request
	if _payload != "" {
		req, _ = http.NewRequest("POST", _url, bytes.NewBuffer([]byte(_payload)))
	} else {
		req, _ = http.NewRequest("GET", _url, nil)
	}

	req.Header.Set("User-Agent", "Instagram "+_api.VERSION+" Android (19/4.4.2; 480dpi; 1080x1920; samsung; SM-N900T; hltetmo; qcom; en_US)")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Cookie2", "$Version=1")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-IG-Connection-Type", "WIFI")
	req.Header.Set("X-IG-Capabilities", _api.CAPABILITIES)
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("X-FB-HTTP-Engine", "Liger")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "Keep-Alive")

	if Headers != nil {
		var keys []string
		for key := range Headers {
			keys = append(keys, key)
		}
		var values []string
		for _, value := range Headers {
			values = append(values, value)
		}

		for i := 0; i < len(keys); i++ {
			req.Header.Set(keys[i], values[i])
		}
	}

	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(_url)
	jar.SetCookies(u, cookie)

	transport := http.Transport{}
	if proxy != "" {
		proxyUrl := &url.URL{Host: proxy}
		transport.Proxy = http.ProxyURL(proxyUrl)
	}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}
	if MiliTimeout != 0 {
		client = &http.Client{Timeout: time.Millisecond * time.Duration(MiliTimeout)}
	}
	if usecookies {
		if MiliTimeout != 0 {
			client = &http.Client{Timeout: time.Millisecond * time.Duration(MiliTimeout), Jar: jar}
		} else {
			client = &http.Client{Jar: jar}
		}
	}

	client.Transport = &transport
	resp, err := client.Do(req)

	RawReq, _ := httputil.DumpRequest(req, true)
	ReqSize := float64(len(RawReq))
	if _payload != "" {
		ReqSize += float64(len([]byte(_payload)))
		ReqSize += 4
	}

	if resp == nil {
		if err != nil {
			return MakeHttpResponse(nil, req, err, ReqSize, 0)
		}
		return MakeHttpResponse(nil, req, nil, ReqSize, 0)
	}
	RawRes, _ := httputil.DumpResponse(resp, true)
	ResSize := float64(len(RawRes))

	if err != nil {
		return MakeHttpResponse(resp, req, err, ReqSize, ResSize)
	}
	defer resp.Body.Close()
	return MakeHttpResponse(resp, req, nil, ReqSize, ResSize)
}

func edit(_api API, Profile map[string]string, sessionID string, _target string, passedClient *http.Client) int {

	params := url.Values{}
	params.Set("email", Profile["email"])
	params.Set("username", _target)
	params.Set("gender", Profile["gender"])
	if Profile["phone_number"] != "" {
		params.Set("phone_number", Profile["phone_number"])
	}

	_url := "https://i.instagram.com/api/v1/accounts/edit_profile/"

	req, _ := http.NewRequest("POST", _url, bytes.NewBuffer([]byte(params.Encode())))

	req.Header.Set("User-Agent", "Instagram "+_api.VERSION+" Android (19/4.4.2; 480dpi; 1080x1920; samsung; SM-N900T; hltetmo; qcom; en_US)")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Cookie2", "$Version=1")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-IG-Connection-Type", "WIFI")
	req.Header.Set("X-IG-Capabilities", _api.CAPABILITIES)
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("X-FB-HTTP-Engine", "Liger")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "Keep-Alive")

	req.AddCookie(&http.Cookie{
		Name:  "sessionid",
		Value: sessionID,
	})

	resp, err := passedClient.Do(req)

	if err != nil {
		return 0
	}

	return resp.StatusCode
}

func set(_api API, _target string, sessionID string, passedClient *http.Client) int {

	_url := "https://i.instagram.com/api/v1/accounts/set_username/"
	req, _ := http.NewRequest("POST", _url, bytes.NewBuffer([]byte("username="+_target)))

	req.Header.Set("User-Agent", "Instagram "+_api.VERSION+" Android (19/4.4.2; 480dpi; 1080x1920; samsung; SM-N900T; hltetmo; qcom; en_US)")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Cookie2", "$Version=1")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-IG-Connection-Type", "WIFI")
	req.Header.Set("X-IG-Capabilities", _api.CAPABILITIES)
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("X-FB-HTTP-Engine", "Liger")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "Keep-Alive")

	req.AddCookie(&http.Cookie{
		Name:  "sessionid",
		Value: sessionID,
	})

	resp, err := passedClient.Do(req)

	if err != nil {
		panic(err)
		return 0
	}

	return resp.StatusCode
}

func webLogin(us string, ps string, timeout int, proxy string) HttpResponse {

	now := time.Now()
	payload := fmt.Sprintf("username=%v&enc_password=#PWD_INSTAGRAM_BROWSER:0:%v:%v", us, now.Unix(), ps)

	_url := "https://www.instagram.com/accounts/login/ajax/"
	req, _ := http.NewRequest("POST", _url, bytes.NewBuffer([]byte(payload)))

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("X-CSRFToken", randomdata.RandStringRunes(15))
	req.Header.Add("X-Instagram-AJAX", "1")
	req.Header.Add("x-requested-with", "XMLHttpRequest")

	transport := http.Transport{}
	if proxy != "" {
		proxyURL := &url.URL{Host: proxy}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}

	client.Transport = &transport
	resp, err := client.Do(req)

	if err == nil {
		var res string
		var StatusCode int
		_ = StatusCode
		_ = res

		var reader io.ReadCloser
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			reader, _ = gzip.NewReader(resp.Body)
			defer reader.Close()
		default:
			reader = resp.Body
		}
		body, _ := ioutil.ReadAll(reader)
		res = string(body)

		if resp.StatusCode != 0 {
			StatusCode = resp.StatusCode
		}
		return MakeHttpResponse(resp, req, err, 0, 0)
	}
	defer resp.Body.Close()
	return MakeHttpResponse(resp, req, err, 0, 0)
}

func webGetProfile(sessionID string) HttpResponse {

	_url := "https://www.instagram.com/accounts/edit/?__a=1"
	req, _ := http.NewRequest("POST", _url, nil)

	req.Header.Add("Referer", "https://www.instagram.com/accounts/edit/")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("X-CSRFToken", randomdata.RandStringRunes(15))
	req.Header.Add("X-Instagram-AJAX", "1")
	req.Header.Add("x-requested-with", "XMLHttpRequest")

	transport := http.Transport{}

	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}

	client.Transport = &transport
	resp, err := client.Do(req)

	if err == nil {
		var res string
		var StatusCode int
		_ = StatusCode
		_ = res

		var reader io.ReadCloser
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			reader, _ = gzip.NewReader(resp.Body)
			defer reader.Close()
		default:
			reader = resp.Body
		}
		body, _ := ioutil.ReadAll(reader)
		res = string(body)

		if resp.StatusCode != 0 {
			StatusCode = resp.StatusCode
		}
		return MakeHttpResponse(resp, req, err, 0, 0)
	}
	defer resp.Body.Close()
	return MakeHttpResponse(resp, req, err, 0, 0)
}

func updateBTH(sessionid string) HttpResponse {

	var cookies []*http.Cookie
	cookie := &http.Cookie{
		Name:  "sessionid",
		Value: sessionid,
	}
	cookies = append(cookies, cookie)

	url := "/consent/update_dob/"

	post := "SIGNATURE.{\"current_screen_key\":\"dob\",\"day\":\"1\",\"year\":\"1998\",\"month\":\"1\"}"
	payload := "ig_sig_key_version=" + _api.KeyVersion + "&signed_body=" + post

	return instRequest(url, nil, payload, nil, GetAPI(), "", cookies, true, 60*1000)
}

func login(us string, ps string, timeout int) HttpResponse {
	url := "https://i.instagram.com/api/v1/accounts/login/"

	var Cookies []*http.Cookie

	u, _ := uuid.NewUUID()
	guid := u.String()

	post := make(map[string]string)
	post["phone_id"] = guid
	post["_csrftoken"] = "missing"
	post["username"] = us
	post["password"] = ps
	post["device_id"] = guid
	post["guid"] = guid
	post["login_attempt_count"] = "0"

	return instRequest(url, post, "", nil, GetAPI(), "", Cookies, true, timeout)
}

func checkBlock(profile map[string]string, post url.Values, sessionID string) HttpResponse {

	var cookies []*http.Cookie
	cookie := &http.Cookie{
		Name:     "sessionid",
		Value:    sessionID,
		Path:     "/",
		Domain:   ".instagram.com",
		Secure:   true,
		HttpOnly: true,
	}
	cookies = append(cookies, cookie)

	url := "https://i.instagram.com/api/v1/accounts/edit_profile/"
	post.Set("username", profile["username"]+".titan")

	return instRequest(url, nil, post.Encode(), nil, GetAPI(), "", cookies, true, 60*1000)
}

func CheckSessionID(sessionID string) bool {

	var cookies []*http.Cookie
	cookie := &http.Cookie{
		Name:     "sessionid",
		Value:    sessionID,
		Path:     "/",
		Domain:   ".instagram.com",
		Secure:   true,
		HttpOnly: true,
	}
	cookies = append(cookies, cookie)

	res := instRequest("accounts/current_user/?edit=true", nil, "", nil, GetAPI(), "", cookies, true, 60*1000)
	if res.ResStatus == 200 {
		return true
	} else {
		return false
	}
}

func logout(sessionID string) bool {

	var cookies []*http.Cookie
	cookie := &http.Cookie{
		Name:     "sessionid",
		Value:    sessionID,
		Path:     "/",
		Domain:   ".instagram.com",
		Secure:   true,
		HttpOnly: true,
	}
	cookies = append(cookies, cookie)

	res := instRequest("accounts/logout/", nil, "", nil, GetAPI(), "", cookies, true, 60*1000)
	if res.ResStatus == 200 {
		return true
	} else {
		return false
	}
}

func GetProfile(sessionID string) (map[string]string, HttpResponse) {

	var cookies []*http.Cookie
	cookie := &http.Cookie{
		Name:     "sessionid",
		Value:    sessionID,
		Path:     "/",
		Domain:   ".instagram.com",
		Secure:   true,
		HttpOnly: true,
	}
	cookies = append(cookies, cookie)

	res := instRequest("accounts/current_user/?edit=true", nil, "", nil, GetAPI(), "", cookies, true, 60*1000)
	var profile = make(map[string]string)

	var username = ""
	_username := regexp.MustCompile("\"username\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _username != nil {
		username = _username[1]
	}

	var biography = ""
	_biography := regexp.MustCompile("\"biography\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _biography != nil {
		biography = _biography[1]
	}

	var fullName = ""
	_fullName := regexp.MustCompile("\"full_name\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _fullName != nil {
		fullName = _fullName[1]
	}

	var phoneNumber = ""
	_phoneNumber := regexp.MustCompile("\"phone_number\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _phoneNumber != nil {
		phoneNumber = _phoneNumber[1]
	}

	var email = ""
	_email := regexp.MustCompile("\"email\": \"(.*?)\"").FindStringSubmatch(res.Body)
	if _email != nil {
		email = _email[1]
	}

	var gender = ""
	_gender := regexp.MustCompile("\"gender\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _gender != nil {
		gender = _gender[1]
	}

	var externalUrl = ""
	_externalUrl := regexp.MustCompile("\"external_url\": \"(.*?)\",").FindStringSubmatch(res.Body)
	if _externalUrl != nil {
		externalUrl = _externalUrl[1]
	}

	profile["username"] = username
	profile["biography"] = biography
	profile["full_name"] = fullName
	profile["phone_number"] = phoneNumber
	profile["email"] = email
	profile["gender"] = gender
	profile["external_url"] = externalUrl

	return profile, res
}

func parseRequest(host string, path string, method string, headers map[string]string, data map[string]string, rawData string, Cookies map[string]string) []byte {

	method = strings.ToUpper(method)
	rawRequest := fmt.Sprintf("%s %s HTTP/1.1\r\n", strings.ToUpper(method), path)

	if method == "GET" && (data != nil || rawData != ``) {
		var rawQuery string
		if rawData != "" {
			rawQuery = rawData
		} else {
			i := 0
			for key, value := range data {
				if i == len(data)-1 {
					rawQuery += fmt.Sprintf("%s=%s", key, value)
				} else {
					rawQuery += fmt.Sprintf("%s=%s&", key, value)
				}
				i++
			}
		}
		query := fmt.Sprintf("%s?%s", path, rawQuery)
		rawRequest = fmt.Sprintf("%s %s HTTP/1.1\r\n", strings.ToUpper(method), query)
	}

	var rawHeaders string
	for key, value := range headers {
		rawHeaders += fmt.Sprintf("%s: %s\r\n", key, value)
	}

	if !strings.Contains(strings.ToLower(rawHeaders), "host") {
		rawRequest += fmt.Sprintf("Host: %s\r\n", host)
	}

	if Cookies != nil {
		cookies := ""
		for key, value := range Cookies {
			cookies += fmt.Sprintf("%s=%s;", key, value)
		}
		rawRequest += fmt.Sprintf("Cookie: %s\r\n", cookies)
	}

	var gzipped []byte
	_data := ""
	if method == "POST" && (data != nil || rawData != "") {

		if rawData != "" {
			_data = rawData
		} else {
			i := 0
			for key, value := range data {
				if i == len(data)-1 {
					_data += fmt.Sprintf("%s=%s", key, value)
				} else {
					_data += fmt.Sprintf("%s=%s&", key, value)
				}
				i++
			}
		}

		var b bytes.Buffer
		gz := gzip.NewWriter(&b)
		if _, err := gz.Write([]byte(_data)); err != nil {
			log.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			log.Fatal(err)
		}
		gzipped = b.Bytes()

		if !strings.Contains(strings.ToLower(rawHeaders), "content-length") {
			rawHeaders += fmt.Sprintf("Content-Length: %s\r\n", strconv.Itoa(len(gzipped)))
		}

	}
	var encodedRequest []byte
	rawRequest += fmt.Sprintf("%s\r\n", rawHeaders)

	encodedRequest = []byte(rawRequest)

	if _data != "" && _data != "NULL?" {
		encodedRequest = append(encodedRequest, gzipped...)
	}

	return encodedRequest
}

// AdvanceLogi
