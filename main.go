package main

import (
	"fmt"
	"os"

	"github.com/olepor/mender-artifact-refac/artifact"
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
	ar := artifact.New()
	err = ar.Parse(f)
	if err != nil {
		fmt.Println("Failed to parse the artifact")
		fmt.Println(err)
		return
	}
	// _, err = ar.Next()
	// if err != nil {
	// 	fmt.Println("Failed to get the payload")
	// 	os.Exit(1)
	// }
	// io.Copy(os.Stdout, r)
}
