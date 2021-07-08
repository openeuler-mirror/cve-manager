package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/astaxie/beego/logs"
	jwt "github.com/dgrijalva/jwt-go"
	"math/rand"
	"time"
)

//PKCS7Padding PKCS7 padding mode
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding reverse operation of padding, delete padding string
func PKCS7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length == 0 {
		return nil, errors.New("加密字符串错误！")
	}
	// Get the length of the padding string
	unPadding := int(origData[length-1])
	// Intercept the slice, delete the padding bytes, and return the plaintext
	return origData[:(length - unPadding)], nil

}

//AesEcrypt Implement encryption
func AesEcrypt(origData []byte, key []byte) ([]byte, error) {
	// Create an instance of an encryption algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	blocMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blocMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//AesDeCrypt Realize decryption
func AesDeCrypt(cypted []byte, key []byte) ([]byte, error) {
	//Create an instance of an encryption algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(cypted))
	blockMode.CryptBlocks(origData, cypted)
	origData, err = PKCS7UnPadding(origData)
	if err != nil {
		return nil, err
	}
	return origData, err
}

//EnPwdCode Encrypted base64
func EnPwdCode(pwd []byte, key []byte) (string, error) {
	result, err := AesEcrypt(pwd, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(result), err
}

//DePwdCode decryption
func DePwdCode(pwd string, key []byte) ([]byte, error) {
	//Decrypt base64 string
	pwdByte, err := base64.StdEncoding.DecodeString(pwd)
	if err != nil {
		return nil, err
	}
	return AesDeCrypt(pwdByte, key)

}

var (
	length  int
	charset string
)

const (
	NUmStr  = "0123456789"
	CharStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	SpecStr = "+=-@#~,.[]()!%^*$"
)

func parseArgs(lens int) {
	length = lens
	charset = "advance"
	flag.Parse()
}

func generatePasswd() string {
	var passwd []byte = make([]byte, length, length)
	var sourceStr string
	if charset == "num" {
		sourceStr = NUmStr
	} else if charset == "char" {
		sourceStr = charset
	} else if charset == "mix" {
		sourceStr = fmt.Sprintf("%s%s", NUmStr, CharStr)
	} else if charset == "advance" {
		sourceStr = fmt.Sprintf("%s%s%s", NUmStr, CharStr, SpecStr)
	} else {
		sourceStr = NUmStr
	}
	fmt.Println("source:", sourceStr)
	for i := 0; i < length; i++ {
		index := rand.Intn(len(sourceStr))
		passwd[i] = sourceStr[index]
	}
	return string(passwd)
}

//GenPrivKey Generate private key
func GenPrivKey(lens int) string {
	rand.Seed(time.Now().UnixNano())
	parseArgs(lens)
	passwd := generatePasswd()
	fmt.Println(passwd)
	fmt.Printf("length:%d charset:%s\n", length, charset)
	return passwd
}

type Claims struct {
	username string
	password string
	jwt.StandardClaims
}

func setting(jwtkey []byte, username, password string) (string, error) {
	expireTime := time.Now().Add(7 * 24 * time.Hour)
	claims := &Claims{
		username: username,
		password: password,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expireTime.Unix(), //expire date
			IssuedAt:  time.Now().Unix(),
			Issuer:    "127.0.0.1",  // Signature issuer
			Subject:   "user token", //Signature subject
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtkey)
	if err != nil {
		logs.Error(err)
		return "", err
	}
	return tokenString, nil
}

//GenToken Generate Token
func GenToken(username, password string) (string, error) {
	pKey := GenPrivKey(16)
	var jwtkey = []byte(pKey)
	tokens, err := setting(jwtkey, username, password)
	return tokens, err
}

////解析token
//func getting(tokenString string) (string, struct{}){
//	token, claims, err := ParseToken(tokenString)
//	if err != nil || !token.Valid {
//		return "", struct{}{}
//	}
//	return token,
//}
//
//func ParseToken(tokenString string) (*jwt.Token, *Claims, error) {
//	Claims := &Claims{}
//	token, err := jwt.ParseWithClaims(tokenString, Claims, func(token *jwt.Token) (i interface{}, err error) {
//		return jwtkey, nil
//	})
//	return token, Claims, err
//}

//EncryptMd5 encrypt md5
func EncryptMd5(str string) string {
	if str == ""{
		return str
	}
	sum := md5.Sum([]byte(str))
	return  fmt.Sprintf("%x",sum)
}

