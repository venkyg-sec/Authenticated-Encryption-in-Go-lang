package main

import (
  "fmt"
  "log"
  "io/ioutil"
  "encoding/hex"
  //"reflect"
  "crypto/sha256"
  "os"
)

func main() {

  file_name := os.Args[1]
  Key := os.Args[2]
  hexHmacKey := Key[32:64]
  Message, err_data_file := ioutil.ReadFile(file_name)
  if (err_data_file != nil) {
    log.Fatal(err_data_file)
  }

  hexHmacKeyBytes, _ := hex.DecodeString(hexHmacKey)
  fmt.Println(hexHmacKeyBytes, " and length is ", len(hexHmacKeyBytes))

  // Hmac function (Arguments - Key and Message)
  hmacSha256(Message, hexHmacKeyBytes)
}

func hmacSha256(Message []byte, hexHmacKeyBytes []byte) {

  // As per HMAC specification, keys greater than the BlockSize are to be
  // shortened to 64 bytes
  hmacSHA256BlockSize := 64
  key := make([]byte,hmacSHA256BlockSize )
  if (len(hexHmacKeyBytes) > hmacSHA256BlockSize) {
    // TODO Some problem with below key (unable to take as a byte array - DEBUG)
    key := sha256.Sum256(hexHmacKeyBytes)
    fmt.Println(key)
  }

  if (len(hexHmacKeyBytes) < hmacSHA256BlockSize) {
    lengthDifference := hmacSHA256BlockSize - len(hexHmacKeyBytes)
    padZeroByte := make([]byte, lengthDifference)
    key := hexHmacKeyBytes
    fmt.Println("Key is ", key)

    for i := 0; i < lengthDifference; i++ {
      padZeroByte[i] = 0x00
      key = append(key,padZeroByte[i])
    }

    fmt.Println(key, " and length is ", len(key))


  }

  opadRep := make([]byte, 64)
  for i := 0; i < 64; i++ {
    opadRep[i] = 0x5c
  }
  fmt.Println(" Opad is " ,opadRep, " and length is ", len(opadRep))

  ipadRep := make([]byte, 64)
  for i := 0; i < 64; i++ {
    ipadRep[i] = 0x36
  }
  fmt.Println(" Ipad is " ,ipadRep, " and length is ", len(ipadRep))

  xorOPadKey := make([]byte, 64)
  xorIPadKey := make([]byte, 64)
  xorOPadKeyLength := XorBytes(xorOPadKey, opadRep, key)
  xorIPadKeyLength := XorBytes(xorIPadKey, ipadRep, key)

  if (xorOPadKeyLength == 0) || (xorIPadKeyLength == 0) {
    fmt.Println("XOR failed")
  }

  iKeyPadMessageConcatenated := make([]byte, xorIPadKeyLength + len(Message))
  iKeyPadMessageConcatenated = xorIPadKey
  for i:=0 ; i < len(Message); i++ {
    iKeyPadMessageConcatenated = append(iKeyPadMessageConcatenated, Message[i])
  }

  hasiKeyPadMessageConcatenated := sha256.Sum256(iKeyPadMessageConcatenated)

  oKeyPadhasiKeyPadMessageConcatenated := make([]byte, xorOPadKeyLength + len(hasiKeyPadMessageConcatenated))
  oKeyPadhasiKeyPadMessageConcatenated = xorOPadKey
  for i := 0; i < len(hasiKeyPadMessageConcatenated); i++ {
    oKeyPadhasiKeyPadMessageConcatenated = append(oKeyPadhasiKeyPadMessageConcatenated,hasiKeyPadMessageConcatenated[i])
  }

  hashoKeyPadhasiKeyPadMessageConcatenated := sha256.Sum256(oKeyPadhasiKeyPadMessageConcatenated)

  fmt.Println("HMAC is ",hashoKeyPadhasiKeyPadMessageConcatenated, " and length is ", len(hashoKeyPadhasiKeyPadMessageConcatenated))



}

/* Function to XOR 2 Byte Arrays */
func XorBytes(ivPlaintext, iv, plaintext []byte) int {

	ivLength := len(iv)
  if len(plaintext) < ivLength {
    ivLength = len(plaintext)

	}

	for i := 0; i < ivLength; i++ {
    ivPlaintext[i] = iv[i] ^ plaintext[i]
  }
  return ivLength
}
