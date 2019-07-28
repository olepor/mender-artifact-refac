package main

import (
	"fmt"
	"io"
	"os"

	"github.com/olepor/ma-go/parser"
)

func main() {
	p := &parser.Parser{}
	if len(os.Args) != 2 {
		fmt.Println("Need a mender-artifact")
		return
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Failed to open the mender-artifact file")
		return
	}
	_, err = io.Copy(p, f)
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
		return
	}
}
