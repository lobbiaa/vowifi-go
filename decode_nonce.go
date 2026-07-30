package main
import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)
func main() {
	nonce := "3vYSA3o/MbFLnmWFtH7rs/gpeCCPegAAR7N89zv8cfs="
	data, _ := base64.StdEncoding.DecodeString(nonce)
	fmt.Printf("RAND: %s\n", hex.EncodeToString(data[:16]))
	fmt.Printf("AUTN: %s\n", hex.EncodeToString(data[16:32]))
}
