package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"time"

	//"unsafe"

	"github.com/Pallinder/go-randomdata"
	"github.com/fatih/color"
)

var request []byte
var APIRequest []byte
var WebRequest []byte
var target string
var loggedIn bool
var Profile map[string]string
var counter uint64
var sent uint64
var start sync.WaitGroup
var stopC bool

var claimed sync.WaitGroup
var blocked sync.WaitGroup
var claimedInt uint64
var claim bool
var newSuccess bool

var _api = GetAPI()
var reader = bufio.NewScanner(os.Stdin)
var params url.Values
var allow bool

//var blockedInt uint64
var sessionid string
var succ uint64
var success uint64
var bypass bool
var EditReq *http.Request
var SetReq *http.Request
var check bool
var blockedWeb int
var TAU string
var sleep int
var loops int
var ClearConsole func()
var iter int
var headers http.Header
var stop bool
var stopB bool
var Final string
var stopS bool
var EditBlocked uint64
var SetBlocked uint64
var discorded bool

var mx sync.Mutex
var wg sync.WaitGroup

var G = color.New(color.FgHiCyan, color.Bold)
var R = color.New(color.FgRed, color.Bold)
var Gr = color.New(color.FgGreen, color.Bold)
var Y = color.New(color.FgYellow, color.Bold)
var w = color.New(color.FgWhite, color.Bold)

var blue = color.New(color.FgBlue, color.Bold)
var green = color.New(color.FgGreen, color.Bold)
var red = color.New(color.FgRed, color.Bold)
var white = color.New(color.FgWhite, color.Bold)
var yellow = color.New(color.FgYellow, color.Bold)

var dicURL = "Your WebHook"

var globalTr = &http.Transport{
	MaxIdleConnsPerHost: 4096,
	MaxIdleConns:        4096,
	MaxConnsPerHost:     4096,
	TLSHandshakeTimeout: 0 * time.Second,
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
			})
		},
	}).DialContext,
}

func end(s int) {

	ClearConsole()

	fmt.Println()
	logo(banner)

	fmt.Println()

	if s == 0 {
		color.Green("Successfully Claimed: " + target)
	} else if s == 1 {
		color.Red("Error ! or it closed by the Developer")
	} else if s == 3 {
		color.Red("Closed")
	}

	fmt.Println()

	fmt.Println()

	os.Exit(0)

}

var DisErr int

func WebHook(url string, log bool) {

	if claimedInt != 0 || claimedInt > 0 {
		return
	}

	if len(target) > 4 {
		if !log {
			return
		}
	}

	data := "{\"embeds\":[{\"description\":\"Swapped Successfully!\\nAttempts: " + fmt.Sprintf("%v", counter) + "\\nBy " + DiscRights + "\",\"title\":\"@" + target + "\",\"color\":12189739,\"author\":{\"name\":\"Titan Swapper\"},\"footer\":{\"text\":\"0xhades, Faisal @3wv\"},\"image\":{\"url\":\"https://i.pinimg.com/originals/f7/f2/fc/f7f2fc20f8b2c357c0131a78fa6e99ae.gif\"}}],\"username\":\"Titan Swapper\"}"

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
	req.Header.Add("Content-Type", "application/json")
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
		atomic.AddUint64(&claimedInt, 1)
	} else {
		DisErr++
		if DisErr > 5 {
			return
		}
		WebHook(url, bypass)
		time.Sleep(time.Millisecond * 250)
	}

}

func logo(i int) {

	if i == 0 {
		color.Red("▄▄▄█████▓ ██▓▄▄▄█████▓ ▄▄▄       ███▄    █ ")
		color.Red("▓  ██▒ ▓▒▓██▒▓  ██▒ ▓▒▒████▄     ██ ▀█   █ ")
		color.Red("▒ ▓██░ ▒░▒██▒▒ ▓██░ ▒░▒██  ▀█▄  ▓██  ▀█ ██▒")
		color.Red("░ ▓██▓ ░ ░██░░ ▓██▓ ░ ░██▄▄▄▄██ ▓██▒  ▐▌██▒")
		color.Red("  ▒██▒ ░ ░██░  ▒██▒ ░  ▓█   ▓██▒▒██░   ▓██░")
		color.Red("  ▒ ░░   ░▓    ▒ ░░    ▒▒   ▓▒█░░ ▒░   ▒ ▒ ")
		color.Red("    ░     ▒ ░    ░      ▒   ▒▒ ░░ ░░   ░ ▒░")
		color.Red("  ░       ▒ ░  ░        ░   ▒      ░   ░ ░ ")
		color.Red("          ░                 ░  ░         ░ ")
	}

}

var banner = 0

var rights = "By Hades, inst: @0xhades"

//DiscRights ..
var DiscRights = "TitanSwapper, @titanswap"

//ClaimingPhrase ..
var ClaimingPhrase = "Successfully Moved"

func getProcessOwner() string {
	stdout, err := exec.Command("ps", "-o", "user=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	return strings.Replace(string(stdout), "\n", "", -1)
}

func main() {

	if runtime.GOOS == "windows" {

		ClearConsole = func() {
			cmd := exec.Command("cmd", "/c", "cls")
			cmd.Stdout = os.Stdout
			cmd.Run()
		}

	} else {

		if getProcessOwner() != "root" {
			R.Println("You need to be root!")
			os.Exit(0)
		}

		maxingFdsLimit()

		ClearConsole = func() {
			print("\033[H\033[2J")
		}

	}

	ClearConsole()
	fmt.Println()
	logo(banner)

	fmt.Println()
	color.HiBlue(rights)
	fmt.Println()

	var outin string

	G.Print("Change Settings (Y/N): ")
	reader.Scan()
	if err := reader.Err(); err != nil {
		panic(err)
	}
	outin = reader.Text()
	outin = strings.Replace(outin, "\n", "", -1)
	if strings.ToLower(outin) == "y" {

		var outin1 string
		G.Print("Change Discord Text (Y/N): ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			panic(err)
		}
		outin1 = reader.Text()
		outin1 = strings.Replace(outin1, "\n", "", -1)
		if strings.ToLower(outin1) == "y" {
			G.Print("New Discord Text (Without 'By'): ")
			reader.Scan()
			if err := reader.Err(); err != nil {
				panic(err)
			}
			outin1 = reader.Text()
			outin1 = strings.Replace(outin1, "\n", "", -1)
			err := ioutil.WriteFile("titan_Discord", []byte(outin1), 0644)
			if err != nil {
				panic(err)
			}
		}

		var outin2 string
		G.Print("Change Title (Y/N): ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			panic(err)
		}
		outin2 = reader.Text()
		outin2 = strings.Replace(outin2, "\n", "", -1)
		if strings.ToLower(outin2) == "y" {
			G.Print("New Title: ")
			reader.Scan()
			if err := reader.Err(); err != nil {
				panic(err)
			}
			outin2 = reader.Text()
			outin2 = strings.Replace(outin2, "\n", "", -1)
			err := ioutil.WriteFile("titan_Title", []byte(outin2), 0644)
			if err != nil {
				panic(err)
			}
		}

		var outin3 string
		G.Print("Change Claiming Phrase (Y/N): ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			panic(err)
		}
		outin3 = reader.Text()
		outin3 = strings.Replace(outin3, "\n", "", -1)
		if strings.ToLower(outin3) == "y" {

			_blue := strings.Split(blue.Sprint("COLOR"), "COLOR")[0]
			_yellow := strings.Split(yellow.Sprint("COLOR"), "COLOR")[0]
			_green := strings.Split(green.Sprint("COLOR"), "COLOR")[0]
			_white := strings.Split(white.Sprint("COLOR"), "COLOR")[0]
			_red := strings.Split(red.Sprint("COLOR"), "COLOR")[0]

			_end := strings.Split(white.Sprint("COLOR"), "COLOR")[1]

			blueOut1 := strings.Split(_blue, ";")[0]
			blueRe := regexp.MustCompile("[0-9]+")
			blueOut2 := blueRe.FindAllString(blueOut1, -1)[0]

			yellowOut1 := strings.Split(_yellow, ";")[0]
			yellowRe := regexp.MustCompile("[0-9]+")
			yellowOut2 := yellowRe.FindAllString(yellowOut1, -1)[0]

			greenOut1 := strings.Split(_green, ";")[0]
			greenRe := regexp.MustCompile("[0-9]+")
			greenOut2 := greenRe.FindAllString(greenOut1, -1)[0]

			whiteOut1 := strings.Split(_white, ";")[0]
			whiteRe := regexp.MustCompile("[0-9]+")
			whiteOut2 := whiteRe.FindAllString(whiteOut1, -1)[0]

			redOut1 := strings.Split(_red, ";")[0]
			redRe := regexp.MustCompile("[0-9]+")
			redOut2 := redRe.FindAllString(redOut1, -1)[0]

			println()
			G.Print("Colors: ")
			blue.Print(blueOut2, " ")
			yellow.Print(yellowOut2, " ")
			green.Print(greenOut2, " ")
			white.Print(whiteOut2, " ")
			red.Print(redOut2)

			G.Print("\nNewline: #n\nTarget: #t\nAttempts: #a\nColor: #color XXX #e, Example (#" + fmt.Sprintf("%v", whiteOut2) + " = white):\n#" + fmt.Sprintf("%v", whiteOut2) + "hello#e = " + color.WhiteString("hello") + "\n\nEnter Your Claiming Format:\n")
			reader.Scan()
			if err := reader.Err(); err != nil {
				panic(err)
			}
			outin3 = reader.Text()
			outin3 = strings.Replace(outin3, "\n", "", -1)

			r := strings.NewReplacer(
				"#t", "0xhades",
				"#n", "\n",
				"#a", "50",
				"#"+fmt.Sprintf("%v", color.FgBlue), _blue,
				"#"+fmt.Sprintf("%v", color.FgYellow), _yellow,
				"#"+fmt.Sprintf("%v", color.FgGreen), _green,
				"#"+fmt.Sprintf("%v", color.FgWhite), _white,
				"#"+fmt.Sprintf("%v", color.FgRed), _red,
				"#e", _end,
			)

			println()
			print(r.Replace(outin3))
			reader.Scan()
			err := ioutil.WriteFile("titan_claiming", []byte(outin3), 0644)
			if err != nil {
				panic(err)
			}
		}

	}

	b, err := ioutil.ReadFile("titan_Discord")
	if err == nil {
		DiscRights = string(b)
	}

	b, err = ioutil.ReadFile("titan_Title")
	if err == nil {
		rights = string(b)
	}

	b, err = ioutil.ReadFile("titan_claiming")
	if err == nil {
		ClaimingPhrase = string(b)
		newSuccess = true
		_blue := strings.Split(blue.Sprint("COLOR"), "COLOR")[0]
		_yellow := strings.Split(yellow.Sprint("COLOR"), "COLOR")[0]
		_green := strings.Split(green.Sprint("COLOR"), "COLOR")[0]
		_white := strings.Split(white.Sprint("COLOR"), "COLOR")[0]
		_red := strings.Split(red.Sprint("COLOR"), "COLOR")[0]

		blueOut1 := strings.Split(_blue, ";")[0]
		blueRe := regexp.MustCompile("[0-9]+")
		blueOut2 := blueRe.FindAllString(blueOut1, -1)[0]

		yellowOut1 := strings.Split(_yellow, ";")[0]
		yellowRe := regexp.MustCompile("[0-9]+")
		yellowOut2 := yellowRe.FindAllString(yellowOut1, -1)[0]

		greenOut1 := strings.Split(_green, ";")[0]
		greenRe := regexp.MustCompile("[0-9]+")
		greenOut2 := greenRe.FindAllString(greenOut1, -1)[0]

		whiteOut1 := strings.Split(_white, ";")[0]
		whiteRe := regexp.MustCompile("[0-9]+")
		whiteOut2 := whiteRe.FindAllString(whiteOut1, -1)[0]

		redOut1 := strings.Split(_red, ";")[0]
		redRe := regexp.MustCompile("[0-9]+")
		redOut2 := redRe.FindAllString(redOut1, -1)[0]

		_end := strings.Split(white.Sprint("COLOR"), "COLOR")[1]

		r := strings.NewReplacer(
			"#n", "\n",
			"#"+fmt.Sprintf("%v", blueOut2), _blue,
			"#"+fmt.Sprintf("%v", yellowOut2), _yellow,
			"#"+fmt.Sprintf("%v", greenOut2), _green,
			"#"+fmt.Sprintf("%v", whiteOut2), _white,
			"#"+fmt.Sprintf("%v", redOut2), _red,
			"#e", _end,
		)

		Final = r.Replace(ClaimingPhrase)
	} else {
		newSuccess = false
	}

	G.Print("Claim new username? (Y/N): ")
	reader.Scan()
	if err := reader.Err(); err != nil {
		panic(err)
	}
	outin = reader.Text()
	outin = strings.Replace(outin, "\n", "", -1)
	if strings.ToLower(outin) == "y" {
		G.Print("target: ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			panic(err)
		}
		_outin := reader.Text()
		_outin = strings.Replace(_outin, "\n", "", -1)
		target = _outin
		G.Print("attempts (skip=Random): ")
		G.Print("target: ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			panic(err)
		}
		noutin := reader.Text()
		noutin = strings.Replace(noutin, "\n", "", -1)
		if noutin == "" {
			counter = uint64(randomdata.Number(1, 100))
		} else {
			_int, err := strconv.ParseInt(noutin, 0, 64)
			if err != nil {
				panic(err)
			}
			counter = uint64(_int)
			if counter > 128 || counter < 128 {
				counter = uint64(randomdata.Number(100, 128))
			}
		}

		WebHook(dicURL, true)

		ClearConsole()
		fmt.Println()
		logo(0)

		fmt.Println()
		color.HiBlue(rights)
		fmt.Println()

		if newSuccess {

			r := strings.NewReplacer(
				"#t", target,
				"#a", fmt.Sprintf("%v", counter),
			)

			Final = r.Replace(Final)
			print(Final)

		} else {

			R.Print("\n" + ClaimingPhrase + ": ")
			w.Print(target + "\n")
			R.Print("Attempts: ")
			w.Println(fmt.Sprintf("%v", counter))

		}
		os.Exit(0)
	}

	ClearConsole()
	var choice string

	checkMemory()

	fmt.Println()
	logo(banner)

	fmt.Println()
	color.HiBlue(rights)
	fmt.Println()

	//var WebReceiverCookiesMap = make(map[string]string)
	var receiverCookiesMap = make(map[string]string)
	var sessioned bool
	//var webSession string

	for {
		G.Print("Session ID[S] / Login [L]: ")
		fmt.Scanln(&choice)
		if strings.ToLower(choice) == "s" {
			G.Print("Enter the API SessionID: ")
			fmt.Scanln(&sessionid)
			var res HttpResponse
			Profile, res = GetProfile(sessionid)
			if strings.Contains(res.Body, "consent_required") {
				updateBTHRes := updateBTH(sessionid)
				if updateBTHRes.ResStatus != 200 {
					println(updateBTHRes.Body)
					color.Red("Error Updating Day of birth")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						end(2)
					} else {
						continue
					}
				}
			}
			Profile, res = GetProfile(sessionid)
			if Profile["username"] != "" {
				for i := 0; i < len(res.Cookies); i++ {
					receiverCookiesMap[res.Cookies[i].Name] = res.Cookies[i].Value
				}
				receiverCookiesMap["sessionid"] = sessionid
				TAU = Profile["username"]
				color.Green("Logged In @" + TAU + " Successfully")
				loggedIn = true
				//time.Sleep(time.Second * 2)
				sessioned = true
				break
			} else {
				println(Profile["username"])
				println(res.Body)
				color.Red("Error Getting Profile 2")
				time.Sleep(time.Second * 2)
				G.Print("Do you wanna try again? [y/n]: ")
				fmt.Scanln(&choice)
				if strings.ToLower(choice) != "y" {
					end(2)
				} else {
					continue
				}
			}
		} else {
			break
		}
	}

	for {
		if sessioned {
			receiverCookiesMap["sessionid"] = sessionid
			break
		}

		G.Print("Enter the username: ")
		fmt.Scanln(&TAU)
		var TAP string
		G.Print("Enter the password: ")
		fmt.Scanln(&TAP)
		var res HttpResponse

		res = login(TAU, TAP, 60*1000)

		for i := 0; i < len(res.Cookies); i++ {
			if res.Cookies[i].Name == "sessionid" {
				loggedIn = true
				println()
				color.Green("Logged In Successfully")
				color.Green("Session ID: " + res.Cookies[i].Value)
				sessionid = res.Cookies[i].Value
				_Res := HttpResponse{}
				Profile, _Res = GetProfile(sessionid)
				if strings.Contains(_Res.Body, "consent_required") || _Res.Res.StatusCode != 200 {
					updateBTHRes := updateBTH(sessionid)
					if updateBTHRes.ResStatus != 200 {
						println(updateBTHRes.Body)
						color.Red("Error Updating Day of birth")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							end(2)
						} else {
							continue
						}
					}
					Profile, _Res = GetProfile(sessionid)
					if Profile["username"] == "" {
						println(_Res.Body)
						color.Red("Error Getting Profile ")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							end(2)
						} else {
							continue
						}
					}
				}
			}
			receiverCookiesMap[res.Cookies[i].Name] = res.Cookies[i].Value
		}

		if strings.Contains(res.Body, "ogged_in") && loggedIn && Profile["username"] != "" {
			break
		} else {
			if strings.Contains(res.Body, "challenge_required") {

				urlRegex := regexp.MustCompile("\"api_path\": \"(.*?)\"").FindStringSubmatch(res.Body)
				var url string

				if urlRegex == nil {
					println(res.Body)
					color.Red("Getting API Path Error")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					} else {
						continue
					}
				}

				url = urlRegex[1]

				_headers := make(map[string]string)
				loginCookies := res.Headers.Get("set-cookie")

				if loginCookies == "" {
					color.Red("Login's set-cookie is empty")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					} else {
						continue
					}
				}

				CSRFRegex := regexp.MustCompile("csrftoken=(.*?);").FindStringSubmatch(loginCookies)
				//MidRegex := regexp.MustCompile("mid=(.*?);").FindStringSubmatch(loginCookies)
				var csrftoken string

				if CSRFRegex == nil {
					println(loginCookies)
					color.Red("CSRF is empty")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					} else {
						continue
					}
				}

				csrftoken = CSRFRegex[1]

				_headers["X-CSRFToken"] = csrftoken

				SecureResult := instRequest(url, nil, "", _headers, GetAPI(), "", res.Cookies, true, 60*1000)

				em := false
				ph := false

				var Pass bool
				var email string
				var phone string
				var emailRegex []string
				var phoneRegex []string

				if strings.Contains(SecureResult.Body, "select_verify_method") {
					if strings.Contains(SecureResult.Body, "email") {
						emailRegex = regexp.MustCompile("\"email\": \"(.*?)\"").FindStringSubmatch(SecureResult.Body)
					}
					if strings.Contains(SecureResult.Body, "phone_number") {
						phoneRegex = regexp.MustCompile("\"phone_number\": \"(.*?)\"").FindStringSubmatch(SecureResult.Body)
					}
				} else {
					choice = "0"
					Pass = true
				}

				var contactPoint string

				if !Pass {
					if phoneRegex == nil && emailRegex == nil {
						println(SecureResult.Body)
						color.Red("No Verify Methods Found")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							return
						} else {
							continue
						}
					}

					if phoneRegex != nil {
						phone = phoneRegex[1]
						ph = true
					}
					if emailRegex != nil {
						email = emailRegex[1]
						em = true
					}

					if em {
						G.Println("1) email [" + email + "]: ")
					}
					if ph {
						G.Println("0) phone number [" + phone + "]: ")
					}

					G.Print("Select Method: ")
					fmt.Scanln(&choice)

					if choice == "0" {
						contactPoint = phone
					}

					if choice == "1" {
						contactPoint = email
					}

					if choice != "1" && choice != "0" {
						println(SecureResult.Body)
						color.Red("Choose a correct verify method")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							return
						} else {
							continue
						}
					}

				}

				SecureResult = instRequest(url, nil, "choice="+choice, nil, GetAPI(), "", res.Cookies, true, 60*1000)

				if strings.Contains(strings.ToLower(SecureResult.Body), "contact_point") {

					G.Println("A code has been sent to " + contactPoint)

					G.Print("Security Code: ")
					fmt.Scanln(&choice)
					choice = strings.Replace(choice, " ", "", -1)

					SecureResult = instRequest(url, nil, "security_code="+choice, nil, GetAPI(), "", res.Cookies, true, 60*1000)

					if strings.Contains(strings.ToLower(SecureResult.Body), "ok") || SecureResult.Res.StatusCode == 200 {

						for i := 0; i < len(SecureResult.Cookies); i++ {
							if SecureResult.Cookies[i].Name == "sessionid" {
								sessioned = true
								loggedIn = true
								println()
								color.Green("Logged In Successfully")
								color.Green("Session ID: " + SecureResult.Cookies[i].Value)
								sessionid = SecureResult.Cookies[i].Value
								_Res := HttpResponse{}
								Profile, _Res = GetProfile(sessionid)
								if strings.Contains(_Res.Body, "consent_required") || _Res.Res.StatusCode != 200 {
									updateBTHRes := updateBTH(sessionid)
									if updateBTHRes.ResStatus != 200 {
										println(updateBTHRes.Body)
										color.Red("Error Updating Day of birth")
										time.Sleep(time.Second * 2)
										G.Print("Do you wanna try again? [y/n]: ")
										fmt.Scanln(&choice)
										if strings.ToLower(choice) != "y" {
											end(2)
										} else {
											continue
										}
									}
									Profile, _Res = GetProfile(sessionid)
									if Profile["username"] == "" {
										println(_Res.Body)
										color.Red("Error Getting Profile ")
										time.Sleep(time.Second * 2)
										G.Print("Do you wanna try again? [y/n]: ")
										fmt.Scanln(&choice)
										if strings.ToLower(choice) != "y" {
											end(2)
										} else {
											continue
										}
									}
								}

							}
							receiverCookiesMap[SecureResult.Cookies[i].Name] = SecureResult.Cookies[i].Value

						}

					} else {
						println(SecureResult.Body)
						println("Code: " + choice)
						color.Red("Sending Activation Code Error")
						time.Sleep(time.Second * 2)
						G.Print("Do you wanna try again? [y/n]: ")
						fmt.Scanln(&choice)
						if strings.ToLower(choice) != "y" {
							return
						} else {
							continue
						}
					}

				} else if SecureResult.Res.StatusCode == 200 {

					for i := 0; i < len(SecureResult.Cookies); i++ {
						if SecureResult.Cookies[i].Name == "sessionid" {
							sessioned = true
							loggedIn = true
							println()
							color.Green("Logged In Successfully")
							color.Green("Session ID: " + SecureResult.Cookies[i].Value)
							sessionid = SecureResult.Cookies[i].Value
							_Res := HttpResponse{}
							Profile, _Res = GetProfile(sessionid)
							if strings.Contains(_Res.Body, "consent_required") || _Res.Res.StatusCode != 200 {
								updateBTHRes := updateBTH(sessionid)
								if updateBTHRes.ResStatus != 200 {
									println(updateBTHRes.Body)
									color.Red("Error Updating Day of birth")
									time.Sleep(time.Second * 2)
									G.Print("Do you wanna try again? [y/n]: ")
									fmt.Scanln(&choice)
									if strings.ToLower(choice) != "y" {
										end(2)
									} else {
										continue
									}
								}
								Profile, _Res = GetProfile(sessionid)
								if Profile["username"] == "" {
									println(_Res.Body)
									color.Red("Error Getting Profile ")
									time.Sleep(time.Second * 2)
									G.Print("Do you wanna try again? [y/n]: ")
									fmt.Scanln(&choice)
									if strings.ToLower(choice) != "y" {
										end(2)
									} else {
										continue
									}
								}
							}
						}
						receiverCookiesMap[SecureResult.Cookies[i].Name] = SecureResult.Cookies[i].Value
					}

				} else {
					println(SecureResult.Body)
					println(SecureResult.Res.Status)
					color.Red("Error choosing verify method")
					time.Sleep(time.Second * 2)
					G.Print("Do you wanna try again? [y/n]: ")
					fmt.Scanln(&choice)
					if strings.ToLower(choice) != "y" {
						return
					} else {
						continue
					}
				}

			}

			if sessioned || sessionid != "" {
				break
			}

			println()
			color.Red("Error Logging into the account")
			println(res.Body)
			time.Sleep(time.Second * 2)
			G.Print("Do you wanna try again? [y/n]: ")
			fmt.Scanln(&choice)
			if strings.ToLower(choice) != "y" {
				end(2)
			} else {
				continue
			}

		}

	}

	ThreadsPerMoment := 1

	println()

	var PM string
	G.Print("Do you want to log this swapping session? (Y/N): ")
	fmt.Scanln(&PM)

	if strings.ToLower(PM) == "y" {
		bypass = true
	} else {
		bypass = false
	}

	for {
		var TPM string
		G.Print("Enter Threads (OverPowered=5, Skip=1): ")
		fmt.Scanln(&TPM)

		if _, err := strconv.Atoi(TPM); err == nil && TPM != "0" && !strings.Contains(TPM, "-") {
			_int64, _ := strconv.ParseInt(TPM, 0, 64)
			ThreadsPerMoment = int(_int64)
			break
		} else {
			if TPM == "" {
				ThreadsPerMoment = 1
				break
			}
			R.Print("Enter a correct number")
			time.Sleep(time.Second * 2)
		}
	}

	for {
		var TPM string
		G.Print("Enter Loops (Ultimate=100, Skip=70): ")
		fmt.Scanln(&TPM)

		if _, err := strconv.Atoi(TPM); err == nil && TPM != "0" && !strings.Contains(TPM, "-") {
			_int64, _ := strconv.ParseInt(TPM, 0, 64)
			loops = int(_int64)
			break
		} else {
			if TPM == "" {
				loops = 70
				break
			}
			R.Print("Enter a correct number")
			time.Sleep(time.Second * 2)
		}
	}

	G.Print("Enter Target: ")
	fmt.Scanln(&target)

	params := url.Values{}
	params.Set("username", target)
	params.Set("email", Profile["email"])
	if Profile["phone_number"] != "" {
		params.Set("phone_number", Profile["phone_number"])
	}

	headers = make(http.Header)
	headers.Set("User-Agent", "Instagram "+_api.VERSION+" Android (19/4.4.2; 480dpi; 1080x1920; samsung; SM-N900T; hltetmo; qcom; en_US)")
	headers.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	headers.Set("Accept", "*/*")
	headers.Set("Connection", "Keep-Alive")

	EditReq, _ = http.NewRequest("POST", "https://i.instagram.com/api/v1/accounts/edit_profile/", bytes.NewBuffer([]byte(params.Encode())))
	SetReq, _ = http.NewRequest("POST", "https://i.instagram.com/api/v1/accounts/set_username/", bytes.NewBuffer([]byte("username="+target)))

	EditReq.Header = headers
	SetReq.Header = headers

	globalCookie = &http.Cookie{
		Name:  "sessionid",
		Value: sessionid,
	}

	EditReq.AddCookie(globalCookie)
	SetReq.AddCookie(globalCookie)

	rand.Seed(time.Now().UnixNano())

	start.Add(1)

	max := loops*5 + 2
	runtime.GOMAXPROCS(max)

	for i := 0; i < ThreadsPerMoment; i++ {
		go sender()
	}

	ClearConsole()

	fmt.Println()
	logo(banner)

	fmt.Println()
	color.HiBlue(rights)
	fmt.Println()

	claimed.Add(1)
	blocked.Add(1)
	go waitClaimed()
	time.Sleep(time.Nanosecond * 10)
	go waitBlocked()
	time.Sleep(time.Nanosecond * 10)

	wg.Add(1)
	checkMemory()

	if runtime.GOOS == "windows" {
		MessageBoxPlain("TitanSwap", "Ready?")
	} else {
		color.Yellow("Click any key to start ...")
		fmt.Scanln()
	}

	start.Done()
	go superVisior(&counter)

	wg.Wait()

	if discorded {
		for {
			if (DisErr > 5) || claimedInt != 0 || claimedInt > 0 {
				break
			}
			time.Sleep(time.Millisecond * 150)
		}
	}

	if runtime.GOOS == "windows" {
		reader.Scan()
	}

}

func checkMemory() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if bToMb(m.Alloc) > 2000 || bToMb(m.TotalAlloc) > 2000 || bToMb(m.Sys) > 2000 {
		R.Println("\nHigh Memory (RAM) Usage, 8 RAM VPS Recommended")
		os.Exit(1)
	}
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func sender() {

	for in := 0; in < 2; in++ {
		go func(init int) {

			var Request *http.Request
			if init == 1 {
				Request = EditReq
			} else {
				Request = SetReq
			}

			for {

				if stop || (SetBlocked >= 15 && EditBlocked >= 15) || (sent >= 120 && counter >= 120) || (sent >= 230 && counter >= 50) || counter >= 120 {
					return
				}

				nb := make(chan nonBlocking)

				var innerLoops int

				if loops != 0 {
					innerLoops = loops
				} else {
					innerLoops = rand.Intn(5)
				}

				if innerLoops == 0 {
					innerLoops = 1
				}

				start.Wait()

				for i := 0; i < innerLoops; i++ {

					go doRequest(nb, Request)
					atomic.AddUint64(&sent, 1)

				}

				go handleResponse(nb)

				if stop || (SetBlocked >= 15 && EditBlocked >= 15) || (sent >= 130 && counter >= 130) || (sent >= 230 && counter >= 50) || counter >= 120 {
					return
				}

				time.Sleep(80 * time.Millisecond)

			}
		}(in)
	}

}

type nonBlocking struct {
	Response *http.Response
	Error    error
}

var globalCookie *http.Cookie

func doRequest(nb chan nonBlocking, request *http.Request) {

	client := &http.Client{
		Transport: globalTr,
	}

	var CopiedBody *bytes.Buffer
	if strings.Contains(request.URL.Path, "set_username") {
		CopiedBody = bytes.NewBuffer([]byte("username=" + target))
	} else {
		CopiedBody = bytes.NewBuffer([]byte(params.Encode()))
	}

	CopiedRequest, _ := http.NewRequest(request.Method, request.URL.String(), CopiedBody)
	CopiedRequest.Header = map[string][]string{
		"Host":         {"i.instagram.com"},
		"User-Agent":   {"Instagram " + _api.VERSION + " Android (19/4.4.2; 480dpi; 1080x1920; samsung; SM-N900T; hltetmo; qcom; en_US)"},
		"Content-Type": {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":       {"*/*"},
		"Connection":   {"Keep-Alive"},
	}
	CopiedRequest.AddCookie(globalCookie)

	resp, err := client.Do(CopiedRequest)
	nb <- nonBlocking{
		Response: resp,
		Error:    err,
	}

}

func handleResponse(nb chan nonBlocking) {

	for post := range nb {

		if stop {
			return
		}

		go func() {

			if post.Error != nil {
				appendToFile("errors.log", post.Error.Error()+"\n")
			} else {

				switch post.Response.StatusCode {
				case 200:

					atomic.AddUint64(&success, 1)

					response := MakeHttpResponse(post.Response, post.Response.Request, post.Error, 0, 0)

					if strings.Contains(response.Body, "\"user\"") || strings.Contains(response.Body, "is_private") || success > 2 {

						mx.Lock()
						if !stopS {
							claim = true
							claimed.Done()
						}
						mx.Unlock()

						atomic.AddUint64(&counter, 1)
						atomic.AddUint64(&succ, 1)

						stop = true
						stopS = true
						return

					}

				case 400:
					atomic.AddUint64(&counter, 1)
				case 429:

					response := MakeHttpResponse(post.Response, post.Response.Request, post.Error, 0, 0)

					if strings.Contains(strings.ToLower(response.Body), "wait") || strings.Contains(strings.ToLower(response.Body), "please") {
						if (counter >= 120 || (SetBlocked >= 15 && EditBlocked >= 15)) && !(success > 3) || counter >= 150 {

							mx.Lock()
							if !stopB {
								blocked.Done()
							}
							mx.Unlock()

							stop = true
							stopB = true
							return
						} else if success > 3 {
							mx.Lock()
							if !stopS {
								claim = true
								claimed.Done()
							}
							mx.Unlock()

							atomic.AddUint64(&counter, 1)
							atomic.AddUint64(&succ, 1)

							stop = true
							stopS = true
							return
						}

						if strings.Contains(response.Req.URL.Path, "set_username") {
							atomic.AddUint64(&SetBlocked, 1)
						}

						if strings.Contains(response.Req.URL.Path, "edit_profile") {
							atomic.AddUint64(&EditBlocked, 1)
						}

					}
				}

				pass := func() { recover() }
				defer pass()
				func() {
					if post.Response.Body != nil && post.Response != nil {
						io.Copy(ioutil.Discard, post.Response.Body)
						post.Response.Body.Close()
					}
				}()

			}
		}()

		if counter > 120 {
			stop = true
			return
		}

		time.Sleep(time.Duration(50) * time.Millisecond)

	}

}

func waitClaimed() {

	claimed.Wait()

	ClearConsole()
	fmt.Println()
	logo(banner)

	fmt.Println()
	color.HiBlue(rights)
	fmt.Println()

	if newSuccess {

		r := strings.NewReplacer(
			"#t", target,
			"#a", fmt.Sprintf("%v", counter),
		)

		Final = r.Replace(Final)
		print(Final)
		discorded = true
		WebHook(dicURL, bypass)

	} else {

		R.Print("\n" + ClaimingPhrase + ": ")
		w.Print(target + "\n")
		R.Print("Attempts: ")
		w.Println(fmt.Sprintf("%v", counter))
		discorded = true
		WebHook(dicURL, bypass)

	}

	stopC = true

}

func waitBlocked() {

	blocked.Wait()
	R.Println(
		"\nYou got blocked for spamming too many requests\nReached: " +
			fmt.Sprintf("%v", counter) + "\nBlocked Req S: " +
			fmt.Sprintf("%v", SetBlocked) + "\nBlocked Req E: " +
			fmt.Sprintf("%v", EditBlocked) +
			"\nSucc: " + fmt.Sprintf("%v", succ) + "\nSuccess: " + fmt.Sprintf("%v", success))

	Y.Print("\nYou Claimed @" + target + " ? (y/n): ")
	reader.Scan()
	if err := reader.Err(); err != nil {
		panic(err)
	}
	outin := reader.Text()
	outin = strings.Replace(outin, "\n", "", -1)
	if strings.ToLower(outin) == "y" {

		WebHook(dicURL, bypass)

		ClearConsole()
		fmt.Println()
		logo(0)

		fmt.Println()
		color.HiBlue(rights)
		fmt.Println()

		if newSuccess {

			r := strings.NewReplacer(
				"#t", target,
				"#a", fmt.Sprintf("%v", counter),
			)

			Final = r.Replace(Final)
			print(Final)

		} else {

			R.Print("\n" + ClaimingPhrase + ": ")
			w.Print(target + "\n")
			R.Print("Attempts: ")
			w.Println(fmt.Sprintf("%v", counter))

		}

	}

	stopC = true

}

func superVisior(c *uint64) {
	for {
		if stopC {
			break
		} else {
			Y.Print("Claiming [" + target + "] - " + fmt.Sprintf("%v", *c) + "\r")
		}
		time.Sleep(time.Millisecond * 50)
	}
	wg.Done()
}

func appendToFile(filename string, data string) error {
	f, err := os.OpenFile(filename,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(data); err != nil {
		return err
	}
	return nil
}
