package main

import (
	"encoding/json"
	"fmt"
	"go-encrypt/utils"
)

type TestObj struct {
	A    int    `json:"a"`
	B    string `json:"b"`
	Ab   int    `json:"ab"`
	Uuid string `json:"uuid"`
	Bo   interface{}   `json:"bo"`
}

func main() {
	ac := utils.AesConfig{
		Iv:  "1234567890qwerty",
		Key: "go-encrypt-tests",
	}
	originData := `{"a":132,"b":"hello world","ab":2,"uuid":"1qaz-2wsx-3edc-4rfv", "bo": null}`
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
