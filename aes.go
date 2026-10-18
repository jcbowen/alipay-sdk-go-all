package alipay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// encryptAES 支付宝敏感信息加密：AES-128-CBC + PKCS7 填充，IV 为 16 个零字节，base64 输出。
//
// 对齐 PHP SDK openssl_encrypt(str, 'aes-128-cbc', key, OPENSSL_NO_PADDING, str_repeat("\0", 16))
// 与 addPKCS7Padding 的组合行为。
//
// 参数:
//   - plainText: 明文（内部先 TrimSpace）
//   - key: AES 密钥（encryptKey 经 base64 解码后的原始字节串，16/24/32 字节）
//
// 返回值:
//   - string: base64 编码密文
//   - error: 密钥长度非法或加密失败时返回错误
func encryptAES(plainText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	data := pkcs7Pad([]byte(strings.TrimSpace(plainText)), block.BlockSize())
	iv := make([]byte, block.BlockSize()) // 零 IV
	cipherText := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(cipherText, data)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// decryptAES 支付宝敏感信息解密：与 encryptAES 对称。
//
// 参数:
//   - cipherText: base64 编码密文
//   - key: AES 密钥原始字节串
//
// 返回值:
//   - string: 解密后的明文
//   - error: base64 解码失败、密文长度非法或 PKCS7 填充非法时返回错误
func decryptAES(cipherText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	if len(data) == 0 || len(data)%block.BlockSize() != 0 {
		return "", errors.New("密文长度不是块大小的整数倍")
	}
	iv := make([]byte, block.BlockSize()) // 零 IV
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(data, data)
	unpadded, err := pkcs7Unpad(data, block.BlockSize())
	if err != nil {
		return "", err
	}
	return string(unpadded), nil
}

// pkcs7Pad PKCS7 填充。
//
// 参数:
//   - data: 待填充数据
//   - blockSize: 块大小（字节）
//
// 返回值:
//   - []byte: 填充后的数据
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

// pkcs7Unpad 移除 PKCS7 填充。
//
// 参数:
//   - data: 已解密的带填充数据
//   - blockSize: 块大小（字节）
//
// 返回值:
//   - []byte: 原始数据
//   - error: 填充非法时返回错误
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("空数据")
	}
	pad := int(data[len(data)-1])
	if pad <= 0 || pad > blockSize || pad > len(data) {
		return nil, fmt.Errorf("非法 PKCS7 填充: %d", pad)
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("非法 PKCS7 填充: %d", pad)
		}
	}
	return data[:len(data)-pad], nil
}
