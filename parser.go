package parser

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

///////////////////////////////////////////////
// Simple parser for the mender-artifact format
///////////////////////////////////////////////

// {
// 	"format": "mender",
// 	"version": 3
// }
type version struct {
	format  string
	version int
}

// Accept the byte body from the tar reader
func (v *version) Reader(b []byte) (n int, err error) {
	if err := json.Unmarshal(b, v); err != nil {
		return 0, err
	}
	return len(b), nil
}

// The signature for the manifest
// 5ac394718e795d454941487c53d32  data/0000/update.ext4
// b7793eb1c57c4694532f96383b619  header.tar.gz
// a343fec7ba3b2983c2ecbbb041a35  version
type manifestData struct {
	signature []byte
	name      string
}

type manifest struct {
	data []manifestData
}

func (m *manifest) Reader(b []byte) (n int, err error) {
	scanner := Scanner(b)
	var line string
	for scanner.HasNext() {
		line := scanner.Next()
		tmp := strings.Split(line, " ")
		append(m.data,
			manifestData{
				signature: tmp[0],
				name:      tmp[1]})
	}
	return len(b), nil
}

// Format: base64 encoded ecdsa or rsa signature
type manifestSig struct {
	// More data
	sig []byte
}

func (m *manifestSig) Reader(b []byte) (n int, err error) {
	m.sig = b
	return len(b), nil
}

// c57c4694532f96383b619  header-augment.tar.gz
// 8e795d454941487c53d32  data/0000/update.delta
type manifestAugment struct {
	// Some Data 4 deltaz
	augData []manifestData
}

func (m *manifestAugment) Reader(b []byte) (n int, err error) {
	scanner := Scanner(b)
	var line string
	for scanner.HasNext() {
		line := scanner.Next()
		tmp := strings.Split(line, " ")
		append(m.data,
			manifestData{
				signature: tmp[0],
				name:      tmp[1]})
	}
	return len(b), nil
}

type headerTar struct {
	headerInfo headerInfo
	scripts    scripts
	headers    headers
}

// +---header.tar.gz (tar format)
//      |
//    	|    +---header-info
//      |
//    	|    +---scripts
//      |    |
//    	|    |    +---State_Enter
//      |    +---State_Leave
//      |    +---State_Error
//      |    `---<more scripts>
//        |
//        `---headers
//           |
//    	|         +---0000
//           |    |
//    	|         |    +---type-info
//           |    |
//    	|         |    +---meta-data
//           |
//    	|         +---0001
//           |    |
//    	|         |    `---<more headers>
//             |
//             `---000n ...
func (h *headerTar) Reader(b []byte) (n int, err error) {
	// The input is gzipped and tarred, so embed the two
	// readers around the byte stream
	// First wrap the gzip writer
	tr := tar.TarReader(gzip.NewReader(bytes.Buffer(b)))
	hdr, err := tr.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name != "header-info" {
		return 0, fmt.Errorf("Unexpected header: %s", hdr.Name)
	}
	// Read the header info
	if _, err = io.Copy(h.headerInfo, r); err != nil {
		return 0, nil
	}
	// Read all the scripts
	for {
		hdr, err = tr.Next()
		if err != nil {
			return 0, err
		}
		if len(hdr.Name) == 4 && atoi(hdr.Name) {
			break // Move on to parsing headers
		}
		if filepath.Dir(hdr.Name) != "scripts" {
			return 0, fmt.Errorf("Expected scripts. Got: %s", hdr.Name)
		}
		if err = h.scripts.Next(filepath.Base(hdr.Name)); err != nil {
			return 0, err
		}
		if _, err = io.Copy(h.scripts, tr); err != nil {
			return 0, err
		}

	}
	// Read all the headers
	for {
		// hdr.Name is already set, as we broke out of the script parsing loop
		if filepath.Base(hdr.Name) != "type-info" {
			return 0, fmt.Errorf("Expected `type-info`. Got %s", hdr.Name) // TODO - this should probs be a parseError type
		}
		sh := subHeader{}
		if _, err = io.Copy(sh.typeInfo, tr); err != nil {
			return 0, err
		}
		hdr, err = tr.Next()
		if err != nil {
			return 0, err
		}
		if filepath.Base(hdr.Name) == "meta-data" {
			_, err = io.Copy(sh.metaData, tr)
			if err != nil {
				return 0, err
			}
			hdr, err = tr.Next()
			if err != nil {
				return 0, err
			}
		}
		append(h.headers, sh)
	}
}

type headerInfo struct {
	// Dataz
	data []byte
}

func (h *headerInfo) Reader(b []byte) (n int, err error) {
	return 0, nil
}

// All the Artifact scripts
type script struct {
	scrpts []string
}

type scripts struct {
	currentScriptName string
	scriptDir         string // `/scripts`
	file              *os.File
}

func (s *scripts) Next(filename string) error {
	f, err := os.Open(filepath.Join(s.scriptDir, filename))
	if err != nil {
		return err
	}
	scripts.file = f
	return nil
}

// The scripts Reader reads a file from the byte stream
// and writes it to /scripts/<ScriptName>
func (s *scripts) Reader(b []byte) (n int, err error) {
	return io.Copy(s.file)
}

type typeInfo struct {
	// type-info
}

func (t *typeInfo) Reader(b []byte) (n int, err error) {
	return io.Copy(ioutil.Discard, bytes.NewReader(b))
}

type metaData struct {
	// meta-data
}

func (t *metaData) Reader(b []byte) (n int, err error) {
	return io.Copy(ioutil.Discard, bytes.NewReader(b))
}

// Wrapper for all the sub-headers
// ie
// 0000 - .
//        |
//        +- type-info
//        |
//        +- meta-data
// 0001 - .
//        |
//        +- type-info
//        |
//        +- meta-data
type subHeader struct {
	name     string
	typeInfo typeInfo
	metaData metaData
}

type headerSubType int

const (
	typeInfoSub headerSubType = iota,
		metaDataSub
)

type headers struct {
	currentWriteType headerSubType
	headers          []subHeader
}

func (h *headers) Reader(b []byte) (n int, err error) {
	return nil, errors.New("Unimplemented")
}

// Another tarball
type headerSigned struct {
	// data
	data       []byte // TODO - What is in the header?
	headerInfo headerInfo
	scripts    scripts
}

// Another tar-ball
// Augmented header is not signed!
type headerAugment struct {
	headerInfo headerInfo
	subHeaders []subHeader
}

func (h *headerAugment) Reader(b []byte) (n int, err error) {
	// The input is gzipped and tarred, so embed the two
	// readers around the byte stream
	// First wrap the gzip writer
	tr := tar.TarReader(gzip.NewReader(bytes.Buffer(b)))
	hdr, err := tr.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name != "header-info" {
		return 0, fmt.Errorf("Unexpected header: %s", hdr.Name)
	}
	// Read the header info
	if _, err = io.Copy(h.headerInfo, r); err != nil {
		return 0, nil
	}
	// Read all the headers
	for {
		// hdr.Name is already set, as we broke out of the script parsing loop
		if filepath.Base(hdr.Name) != "type-info" {
			return 0, fmt.Errorf("Expected `type-info`. Got %s", hdr.Name) // TODO - this should probs be a parseError type
		}
		sh := subHeader{}
		if _, err = io.Copy(sh.typeInfo, tr); err != nil {
			return 0, err
		}
		hdr, err = tr.Next()
		if err != nil {
			return 0, err
		}
		if filepath.Base(hdr.Name) == "meta-data" {
			_, err = io.Copy(sh.metaData, tr)
			if err != nil {
				return 0, err
			}
			hdr, err = tr.Next()
			if err != nil {
				return 0, err
			}
		}
		append(h.headers, sh)
	}
}

type payLoad struct {
	// Give me morez!
}

func (p *payLoad) Reader(b []byte) (n int, err error) {
	tr := tar.NewReader(gzip.NewReader(b))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return len(b), nil
		}
		if err != nil {
			return 0, err
		}
		f, err := os.Open(filepath.Base(hdr.Name))
		if err != nil {
			return 0, err
		}
		_, err := io.Copy(f, tr)
		if err != nil {
			return 0, err
		}
	}
}

//     data
//        |
//        +---0000.tar.gz
//        |    +--<image-file (ext4)>
//        |    +--<binary delta, etc>
//        |     --...
//        |
//        +---0001.tar.gz
//        |    +--<image-file (ext4)>
// 	  |    +--<binary delta, etc>
// 	  |     --...
//        |
//        +---000n.tar.gz ...
//             `--...
type data struct {
	// Updates 4 all ^^
	payloads []payLoad
}

func (d *data) Reader(b []byte) (n int, err error) {
	p := payLoad{}
	n, err := io.Copy(p, bytes.NewReader(b))
	if err != nil {
		return n, err
	}
	append(p.payloads, p)
	return len(b), nil
}

type Parser struct {
	// The parser
	lexer *Lexer
}

func New(lexer *Lexer) *Parser {
	return Parser{lexer}
}
