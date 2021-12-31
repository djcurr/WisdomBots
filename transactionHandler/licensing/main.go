package licensing

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

func errorHandle(err error) {
	fmt.Println("[ERROR]An error has occurred. Please contact your seller.")
	os.Exit(0)
}

func CheckFileExist(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}

func Encrypt(keyString string, stringToEncrypt string) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func Decrypt(keyString string, encryptedString string) (decryptedString string) {

	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprint(plaintext)
}

func CheckPresaleBotLicense(api string, ssl bool, silent bool) {
	if !CheckFileExist("license.dat") {
		if !silent {
			fmt.Println("license.dat not found.")
		}
		os.Exit(0)
	}

	li, err := ioutil.ReadFile("license.dat") //string(li)
	if err != nil {
		if !silent {
			errorHandle(err)
		}
	}

	if ssl {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		data := url.Values{}
		data.Set("license", string(li))
		u, _ := url.ParseRequestURI(api + "presalebot")
		urlStr := fmt.Sprintf("%v", u)
		r, _ := http.NewRequest("POST", urlStr, bytes.NewBufferString(data.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(r)
		if err != nil {
			if !silent {
				fmt.Println("Unable to connect to license server.")
			}
			os.Exit(0)
		}
		defer resp.Body.Close()
		resp_body, _ := ioutil.ReadAll(resp.Body)
		if resp.StatusCode == 200 {
			if string(resp_body) != "Good" {
				if string(resp_body) == "Expired" {
					if !silent {
						fmt.Println("License is Expired.")
					}
					os.Exit(0)
				} else {
					if !silent {
						fmt.Println("Connot verify license, Please contact your seller.")
					}
					os.Exit(0)
				}
			}
		}
	} else {
		client := &http.Client{}
		data := url.Values{}
		data.Set("license", string(li))
		u, _ := url.ParseRequestURI(api + "check")
		urlStr := fmt.Sprintf("%v", u)
		r, _ := http.NewRequest("POST", urlStr, bytes.NewBufferString(data.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(r)
		if err != nil {
			if !silent {
				fmt.Println("Unable to connect to license server.")
			}
			os.Exit(0)
		}
		defer resp.Body.Close()
		resp_body, _ := ioutil.ReadAll(resp.Body)
		if resp.StatusCode == 200 {
			if string(resp_body) != "Good" {
				if string(resp_body) == "Expired" {
					if !silent {
						fmt.Println("License is Expired.")
					}
					os.Exit(0)
				} else {
					if !silent {
						fmt.Println("Connot verify license, Please contact your seller.")
					}
					os.Exit(0)
				}
			}
		}
	}
}

func CheckTelegramBotLicense(api string, ssl bool, silent bool) {
	if !CheckFileExist("license.dat") {
		if !silent {
			fmt.Println("license.dat not found.")
		}
		os.Exit(0)
	}

	li, err := ioutil.ReadFile("license.dat") //string(li)
	if err != nil {
		if !silent {
			errorHandle(err)
		}
	}

	if ssl {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		data := url.Values{}
		data.Set("license", string(li))
		u, _ := url.ParseRequestURI(api + "telegrambot")
		urlStr := fmt.Sprintf("%v", u)
		r, _ := http.NewRequest("POST", urlStr, bytes.NewBufferString(data.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(r)
		if err != nil {
			if !silent {
				fmt.Println("Unable to connect to license server.")
			}
			os.Exit(0)
		}
		defer resp.Body.Close()
		resp_body, _ := ioutil.ReadAll(resp.Body)
		if resp.StatusCode == 200 {
			if string(resp_body) != "Good" {
				if string(resp_body) == "Expired" {
					if !silent {
						fmt.Println("License is Expired.")
					}
					os.Exit(0)
				} else {
					if !silent {
						fmt.Println("Connot verify license, Please contact your seller.")
					}
					os.Exit(0)
				}
			}
		}
	} else {
		client := &http.Client{}
		data := url.Values{}
		data.Set("license", string(li))
		u, _ := url.ParseRequestURI(api + "check")
		urlStr := fmt.Sprintf("%v", u)
		r, _ := http.NewRequest("POST", urlStr, bytes.NewBufferString(data.Encode()))
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(r)
		if err != nil {
			if !silent {
				fmt.Println("Unable to connect to license server.")
			}
			os.Exit(0)
		}
		defer resp.Body.Close()
		resp_body, _ := ioutil.ReadAll(resp.Body)
		if resp.StatusCode == 200 {
			if string(resp_body) != "Good" {
				if string(resp_body) == "Expired" {
					if !silent {
						fmt.Println("License is Expired.")
					}
					os.Exit(0)
				} else {
					if !silent {
						fmt.Println("Connot verify license, Please contact your seller.")
					}
					os.Exit(0)
				}
			}
		}
	}
}
