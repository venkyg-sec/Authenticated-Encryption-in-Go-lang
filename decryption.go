package main

import (
  "fmt"
  "io/ioutil"
  "encoding/hex"
  "log"
  "os"
  "crypto/aes"
  //"reflect"
)

func main() {

  if (len(os.Args[1:]) < 1) {
    fmt.Println(" Use the command line specification mentioned in the Assignment\n")

  } else {
  file_name := os.Args[1]
  ciphertext, err_data_file := ioutil.ReadFile(file_name)

  Key := os.Args[2]
  hexAesKey := Key[0:32]
  //  TODO Uncomment below line while having HMAC
//  hexHmacKey := Key[32:64]

  hexAesKeyBytes, _ := hex.DecodeString(hexAesKey)
  /* Error handling if file wasn't opened successfully */
  if (err_data_file != nil) {
    log.Fatal(err_data_file)
  }

  cipher_block, error_block := aes.NewCipher(hexAesKeyBytes)

  iv := []byte("ThisistheIVfor12")

  // Printing type of the cipher_block retrurned
  //fmt.Println(reflect.TypeOf(cipher_block))

  if (error_block != nil) {
    fmt.Println("Key size error")
    }

  aesBlocksize := 16
  fmt.Println(" Cipher text length is ", len(ciphertext))

  // For handling case where size of ciphertext is less then aesBlocksize
  if len(ciphertext) == 16 {
  plaintext := make([]byte, aesBlocksize)
  ivBlock1 := iv
  cipher_block.Decrypt(plaintext[:aesBlocksize],ciphertext[:aesBlocksize])
  numberOfBytes := XorBytes(plaintext[:aesBlocksize],
    ivBlock1, plaintext[:aesBlocksize])
  fmt.Println(" Number of bytes XOR'ed", numberOfBytes)
  fmt.Println("plaintext is ", string(plaintext))
  }



  if len(ciphertext) > 16 {

    multipleVal := len(ciphertext) / 16
    plaintext :=  make([]byte, aesBlocksize * multipleVal)
    fmt.Println("Number of blocks is", multipleVal)
    // For handling first block
    ivBlock1 := iv
    cipher_block.Decrypt(plaintext[:aesBlocksize],ciphertext[:aesBlocksize])
    numberOfBytes := XorBytes(plaintext[:aesBlocksize],
      ivBlock1, plaintext[:aesBlocksize])
    fmt.Println(" Number of bytes XOR'ed", numberOfBytes)

    // For handling rest of the blocks

    for i := 1; i < multipleVal; i++ {

        cipher_block.Decrypt(plaintext[(aesBlocksize * i):(aesBlocksize  * (i + 1))],
        ciphertext[(aesBlocksize * i):(aesBlocksize * (i+1))])

          // Xor the output of decryption with the IV

          numberOfBytes = XorBytes(plaintext[(aesBlocksize * i):(aesBlocksize *(i + 1))],
          ciphertext[(aesBlocksize * (i -1)): (aesBlocksize * i)] ,
          plaintext[(aesBlocksize * i):(aesBlocksize  *(i + 1))] )
          fmt.Println(" Number of bytes XOR'ed", numberOfBytes)
            }

    paddingByte := plaintext[(multipleVal * aesBlocksize) - 1]
    plaintext = plaintext[:((multipleVal * aesBlocksize) - (int)(paddingByte) - 1)]

    

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
