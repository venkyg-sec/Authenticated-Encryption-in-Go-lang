package main

import (
  "fmt"
  //"crypto/sha256"
  "crypto/rand"
  "io/ioutil"
  "encoding/hex"
  "log"
  "os"
//  "regexp"
  "crypto/aes"
  //"reflect"
)

func main() {

  if (len(os.Args[1:]) < 1) {
    fmt.Println(" Use the command line specification mentioned in the Assignment\n")

  } else {
  file_name := os.Args[1]
  plaintext, err_data_file := ioutil.ReadFile(file_name)

  Key := os.Args[2]
  hexAesKey := Key[0:32]
  //  TODO Uncomment below line while having HMAC
//  hexHmacKey := Key[32:64]

  hexAesKeyBytes, _ := hex.DecodeString(hexAesKey)
  /* Error handling if file wasn't opened successfully */
  if (err_data_file != nil) {
    log.Fatal(err_data_file)
  }
  // re := regexp.MustCompile(`\r?\n`)
  // input := re.ReplaceAllString(string(file), "")

  /* Below is the region I'm testing encryption functionality */
  //key := []byte("1234567891234567")
  cipher_block, error_block := aes.NewCipher(hexAesKeyBytes)

  // plaintext := []byte("123456789123asdasdsdasdasdasd12390sadasd
  //   asdasdasasd1239j983h498h2r9329r3n29uen329un239u4n39u2nd29udn")

  //iv := []byte("ThisistheIVfor12")
  iv := make([]byte,16)
  n, err := rand.Read(iv)
  if err != nil {
    fmt.Println(" Error generating a pseudo Random number")
  }
  fmt.Println("IV is ", iv , " and length is  ", n)
  ivPlaintext := make([]byte, 16)

  // Printing type of the cipher_block retrurned
  //fmt.Println(reflect.TypeOf(cipher_block))

  if (error_block != nil) {
    fmt.Println("Key size error")
    }


  fmt.Println(plaintext)
  aesBlocksize := 16
  if len(plaintext) < 16 {
    residue := 16 - len(plaintext)
    for i := 0; i < residue; i++ {
      plaintext = append(plaintext, byte(residue))

    }
    numberOfBytes := XorBytes(ivPlaintext, iv, plaintext)
    fmt.Println(numberOfBytes)
    fmt.Println(" The XOR of IV and Plaintext is ", ivPlaintext)
    cipherText := make([]byte, aes.BlockSize)

    cipher_block.Encrypt(cipherText,ivPlaintext)

    //fmt.Printf("%x", ciphertext)
    fmt.Println(string(cipherText))

  } else if (len(plaintext) >= 16) {
    multipleVal := (len(plaintext)) / 16
    fmt.Println("Number of blocks is ", multipleVal, " and length is ", len(plaintext))
    residue := 0
    if (len(plaintext) % 16 == 0) {
      residue = 16
    } else {
    residue = ((multipleVal + 1) * 16 ) - len(plaintext)
    }
    for i:=0 ; i < residue ; i++ {
      plaintext = append(plaintext, byte(residue))
    }
    fmt.Println(plaintext, " and length is ", len(plaintext))
    ivBlock1 := iv
    numberOfBytes := XorBytes(ivPlaintext, ivBlock1, plaintext[0:aesBlocksize])
    fmt.Println("Number of bytes XOR'ed is", numberOfBytes)
    cipherText := make([]byte, aesBlocksize * (multipleVal + 1))
    fmt.Println(" Length of ciphertext block is ", len(cipherText))

    cipher_block.Encrypt(cipherText[0:aesBlocksize],ivPlaintext)
    fmt.Println(" Iv for the next block",cipherText[0:aesBlocksize] )

    for i := 1; i <= multipleVal ; i++ {


      numberOfBytes := XorBytes(ivPlaintext,
      cipherText[((i -1)* aesBlocksize):(i * aesBlocksize)],
      plaintext[(aesBlocksize * i):(aesBlocksize* (i+1))])


      fmt.Println("Number of bytes XOR'ed is", numberOfBytes)
      cipher_block.Encrypt(cipherText[(i*aesBlocksize):((i+1)*aesBlocksize)],
      ivPlaintext)

    }
    //fmt.Println(string(cipherText))

    err := ioutil.WriteFile("ciphertext", cipherText, 0644)
    if err != nil {
      log.Fatal(err_data_file)
    }
  }

  }
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
