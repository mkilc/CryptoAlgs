package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/nacl/box"
)

/*{ hello: 'world' } AXdnNAip25GX27BZ0ANmEGo4/+ESddIMtqaTeQRZtBO36zv63rXwTV63WpMopoAndL8OBDTmZ4eW { hello: 'world' }
AXdnNAip25GX27BZ0ANmEGo4/+ESddIMtqaTeQRZtBO36zv63rXwTV63WpMopoAndL8OBDTmZ4eW Uint8Array(32) [
104, 221, 208, 102,  15,  35, 246, 231, 249,  66, 245,  59, 251,  93, 131,  24, 87,  16, 157,  11, 176,  82, 213, 229, 228, 194,  68, 207, 208, 208, 174, 103
] 68ddd0660f23f6e7f942f53bfb5d831857109d0bb052d5e5e4c244cfd0d0ae67
*/
func main() {
	//dataKey := "ReTt8kme9NC8k1dmEbeTpnj+EL6uWQGatRhnXg+qFnM="
	//key, err := base64.StdEncoding.DecodeString(dataKey)
	//if err != nil {
	//	panic(err)
	//}

	dataKey := "68ddd0660f23f6e7f942f53bfb5d831857109d0bb052d5e5e4c244cfd0d0ae67"
	// Setup key
	var k [32]byte
	if n, err := hex.Decode(k[:], []byte(dataKey)); err != nil || n != len(k) {
		fmt.Printf("Failed to decode hex key: %v", err)
		os.Exit(-1)
	}

	encrypted := "AXdnNAip25GX27BZ0ANmEGo4/+ESddIMtqaTeQRZtBO36zv63rXwTV63WpMopoAndL8OBDTmZ4eW"
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		panic(err)
	}

	// Setup the nonce
	var decryptNonce [24]byte
	copy(decryptNonce[:], data[:24])

	dec, ok := box.OpenAfterPrecomputation(nil, data[24:], &decryptNonce, &k)
	fmt.Println(ok)

	if !ok {
		panic("failed decryption")
	}

	fmt.Println(string(dec))
}
