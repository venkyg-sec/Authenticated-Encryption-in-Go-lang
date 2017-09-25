package main

import (
  "fmt"
  "crypto/sha256"
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

  if (len(os.Args[1:]) < 4) {

    fmt.Println(" Use the command line specification mentioned in the Assignment\n <file-name-executable> <input-file-name(plaintext or ciphertext)>  <64 character key> < encrypt or decrypt> <outputFileName>")

  } else {
  file_name := os.Args[1]
  fileContent, err_data_file := ioutil.ReadFile(file_name)

  Key := os.Args[2]
  hexAesKey := Key[0:32]



  iv := make([]byte,16)
  n, err := rand.Read(iv)
  if err != nil {
    fmt.Println(" Error generating a pseudo Random number")
  }
  fmt.Println("IV is ", iv , " and length is  ", n)

  operation := os.Args[3] // Should be encrypt or decrypt
  outputFileName := os.Args[4]
  hexAesKeyBytes, _ := hex.DecodeString(hexAesKey)
  /* Error handling if file wasn't opened successfully */
  if (err_data_file != nil) {
    log.Fatal(err_data_file)
  }

  if operation == "encrypt" {
    hexHmacKey := Key[32:64]
    hexHmacKeyBytes, _ := hex.DecodeString(hexHmacKey)
    encryptionAesCBC(iv, fileContent , hexAesKeyBytes,hexHmacKeyBytes, outputFileName)
  } else if operation == "decrypt" {
    decryptionAesCBC(fileContent, hexAesKeyBytes, outputFileName)
  } else {
    fmt.Println("Invalid operation\n Follow the command line specification")
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

func encryptionAesCBC(iv []byte, plaintext []byte, hexAesKeyBytes []byte, hexHmacKeyBytes []byte, cipherTextFile string) {
  /* Below is the region I'm testing encryption functionality */
  //key := []byte("1234567891234567")
  cipher_block, error_block := aes.NewCipher(hexAesKeyBytes)
  hmac := hmacSha256(plaintext, hexHmacKeyBytes)
  fmt.Println("HMAC is ", hmac)

  ivPlaintext := make([]byte, 16)

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

    fmt.Println("Length of ciphertext before concatenation", len(cipherText))
    ivCiphertextConcatenated := make([]byte, len(iv) + len(cipherText))
    ivCiphertextConcatenated = iv


    for i := 0; i < len(cipherText); i++ {
      ivCiphertextConcatenated = append(ivCiphertextConcatenated,
      cipherText[i])
    }
    fmt.Println("Length of ciphertext after concatenation", len(ivCiphertextConcatenated))
    //fmt.Println(string(cipherText))

    err := ioutil.WriteFile(cipherTextFile, ivCiphertextConcatenated, 0644)
    if err != nil {
      fmt.Println("Error opening file")
    }
  }


}

func decryptionAesCBC(ivCiphertextConcatenated []byte, hexAesKeyBytes []byte, recoveredPlaintextFile string) {

  cipher_block, error_block := aes.NewCipher(hexAesKeyBytes)

  ivLength := 16
  iv := ivCiphertextConcatenated[:ivLength]
  fmt.Println(" IV during decryption is ", iv)
  ciphertext := make([]byte, len(ivCiphertextConcatenated) - 16)
  ciphertext = ivCiphertextConcatenated[ivLength:len(ivCiphertextConcatenated)]

  //iv := []byte("ThisistheIVfor12")

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

    err := ioutil.WriteFile(recoveredPlaintextFile, plaintext, 0644)
    if err != nil {
      fmt.Println("Error opening file")
    }

  }

}


func hmacSha256(Message []byte, hexHmacKeyBytes []byte) ([32]byte) {

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

  return hashoKeyPadhasiKeyPadMessageConcatenated



}
