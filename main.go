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
	ar := parser.NewArtifactReader()
	_, err = ar.Parse(f)
	if err != nil {
		fmt.Println("Failed to parse the artifact")
		fmt.Println(err)
		return
	}
	// fmt.Println(artifact)
	// fmt.Println(artifact.Manifest)
}
