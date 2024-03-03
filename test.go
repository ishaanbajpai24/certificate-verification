package main

import(
	"fmt"
	"os"
	"encoding/pem"
	"crypto/x509"

)

func main(){
	data, err := os.ReadFile("./certs/github.com.cer")
	if err == nil{
		block, _ := pem.Decode(data)
		certificate, _ := x509.ParseCertificate(block.Bytes)
		
		fmt.Println(certificate.Extensions)
	}

	fmt.Println(err)
}