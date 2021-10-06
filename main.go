package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

/*
AES加密
CBC模式
Pkcs7 padding
*/

type AesConfig struct {
	Key string
	Iv  string
}

// Encode 开始加密
func (a *AesConfig) Encode(data string) (string, error) {
	_data := []byte(data)
	_key := []byte(a.Key)
	_iv := []byte(a.Iv)

	_data = a.PKCS7Padding(_data)
	block, err := aes.NewCipher(_key)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, _iv)
	mode.CryptBlocks(_data, _data)
	return base64.StdEncoding.EncodeToString(_data), nil
}

// Decode 开始解密
func (a *AesConfig) Decode(data string) (string, error) {
	_data, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	_key := []byte(a.Key)
	_iv := []byte(a.Iv)

	block, err := aes.NewCipher(_key)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, _iv)
	mode.CryptBlocks(_data, _data)
	_data = a.PKCS7UnPadding(_data)

	return string(_data), nil
}
func (a *AesConfig) PKCS7Padding(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}
func (a *AesConfig) PKCS7UnPadding(data []byte) []byte {
	length := len(data)
	unPadding := int(data[length-1])
	return data[:(length - unPadding)]
}

type TestObj struct {
	A    int    `json:"a"`
	B    string `json:"b"`
	Ab   int    `json:"ab"`
	Uuid string `json:"uuid"`
}

func main() {
	ac := AesConfig{
		Iv:  "1234567890qwerty",
		Key: "go-encrypt-tests",
	}
	originData := `{"a":132,"b":"hello world","ab":2,"uuid":"1qaz-2wsx-3edc-4rfv"}`
	encode, err := ac.Encode(originData)
	if err != nil {
		panic(err)
	}
	fmt.Printf("加密后的内容：%s\n", encode)
	decode, err := ac.Decode(encode)
	fmt.Println("解密后的数据为：", decode)
	if err != nil {
		panic(err)
	}
	var obj TestObj
	err = json.Unmarshal([]byte(decode), &obj)
	if err != nil {
		panic(err)
	}
	fmt.Println("json序列化后的数据为：", obj)
}
