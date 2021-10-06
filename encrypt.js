const {AES, enc, mode, pad} = require('crypto-js');  //引用AES源码js

const key = "go-encrypt-tests";  //十六位十六进制数作为密钥
const iv = '1234567890qwerty';   //十六位十六进制数作为密钥偏移量

function parse(str) {
    return enc.Utf8.parse(str);
}

//解密方法
function Decrypt(code, secret_key, iv) {
    return AES.decrypt(code, parse(secret_key), {
        iv: parse(iv),
        mode: mode.CBC,
        padding: pad.Pkcs7
    }).toString(enc.Utf8);
}

//加密方法
function Encrypt(data, secret_key, iv) {
    return AES.encrypt(parse(data), parse(secret_key), {
        iv: parse(iv),
        mode: mode.CBC,
        padding: pad.Pkcs7
    }).toString();
}

const obj = {a: 132, b: "hello world", ab: 2, uuid: "1qaz-2wsx-3edc-4rfv"}
const encryptData = Encrypt(JSON.stringify(obj), key, iv);
console.log(`加密后的内容：${encryptData}`)

console.log(`解密后的内容：${Decrypt(encryptData, key, iv)}`)
