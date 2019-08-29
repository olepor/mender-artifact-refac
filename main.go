package main

import (
	"fmt"
	"os"

	"github.com/olepor/ma-go/parser"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Need a mender-artifact")
		return
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Failed to open the mender-artifact file")
		return
	}
	ar, err := parser.NewReader(f)
	if err != nil {
		fmt.Printf("error: Failed to initialize the artifact reader with: %s\n", err.Error())
		fmt.Println(ar.Artifact)
		return
	}
	fmt.Println(ar)
}
