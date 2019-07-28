package parser

import (
	"archive/tar"
	"bufio"
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
type Version struct {
	format  string
	version int
}

// Accept the byte body from the tar reader
func (v *Version) Write(b []byte) (n int, err error) {
	if err := json.Unmarshal(b, v); err != nil {
		return 0, err
	}
	return len(b), nil
}

// The signature for the manifest
// 5ac394718e795d454941487c53d32  data/0000/update.ext4
// b7793eb1c57c4694532f96383b619  header.tar.gz
// a343fec7ba3b2983c2ecbbb041a35  version
type ManifestData struct {
	signature string
	name      string
}

type Manifest struct {
	data []ManifestData
}

func (m *Manifest) Write(b []byte) (n int, err error) {
	r := bytes.NewBuffer(b)
	scanner := bufio.NewScanner(r)
	var line string
	for scanner.HasNext() {
		line := scanner.Next()
		tmp := strings.Split(line, " ")
		m.data = append(m.data,
			ManifestData{
				signature: tmp[0],
				name:      tmp[1]})
	}
	return len(b), nil
}

// Format: base64 encoded ecdsa or rsa signature
type ManifestSig struct {
	// More data
	sig []byte
}

func (m *ManifestSig) Write(b []byte) (n int, err error) {
	m.sig = b
	return len(b), nil
}

// c57c4694532f96383b619  header-augment.tar.gz
// 8e795d454941487c53d32  data/0000/update.delta
type ManifestAugment struct {
	// Some Data 4 deltaz
	augData []ManifestData
}

func (m *ManifestAugment) Write(b []byte) (n int, err error) {
	br := bytes.NewReader(b)
	scanner := bufio.NewScanner(br)
	var line string
	for scanner.HasNext() {
		line := scanner.Next()
		tmp := strings.Split(line, " ")
		m.augData = append(m.augData,
			ManifestData{
				signature: tmp[0],
				name:      tmp[1]})
	}
	return len(b), nil
}

type HeaderTar struct {
	headerInfo HeaderInfo
	scripts    Scripts
	headers    []SubHeader
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
func (h *HeaderTar) Write(b []byte) (n int, err error) {
	// The input is gzipped and tarred, so embed the two
	// readers around the byte stream
	// First wrap the gzip writer
	zr, err := gzip.NewReader(bytes.NewBuffer(b))
	if err != nil {
		return 0, err
	}
	tr := tar.NewReader(zr)
	hdr, err := tr.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name != "header-info" {
		return 0, fmt.Errorf("Unexpected header: %s", hdr.Name)
	}
	// Read the header info
	if _, err = io.Copy(h.headerInfo, tr); err != nil {
		return 0, nil
	}
	// Read all the scripts
	for {
		hdr, err = tr.Next()
		if err != nil {
			return 0, err
		}
		if len(hdr.Name) == 4 { //  && atoi(hdr.Name) { TODO -- fixup
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
		sh := SubHeader{}
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
		h.headers = append(h.headers, sh)
	}
}

type HeaderInfo struct {
	// Dataz
	data []byte
}

func (h HeaderInfo) Write(b []byte) (n int, err error) {
	return 0, nil
}

// All the Artifact scripts
type script struct {
	// Identity
}

type Scripts struct {
	currentScriptName string
	scriptDir         string // `/scripts`
	file              *os.File
}

func (s Scripts) Next(filename string) error {
	f, err := os.Open(filepath.Join(s.scriptDir, filename))
	if err != nil {
		return err
	}
	s.file = f
	return nil
}

// The scripts Write reads a file from the byte stream
// and writes it to /scripts/<ScriptName>
func (s Scripts) Write(b []byte) (n int, err error) {
	_, err = io.Copy(s.file, bytes.NewReader(b))
	return len(b), err
}

type TypeInfo struct {
	// type-info
}

func (t TypeInfo) Write(b []byte) (n int, err error) {
	_, err = io.Copy(ioutil.Discard, bytes.NewReader(b))
	return len(b), err
}

type MetaData struct {
	// meta-data
}

func (t MetaData) Write(b []byte) (n int, err error) {
	_, err = io.Copy(ioutil.Discard, bytes.NewReader(b))
	return len(b), err
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
type SubHeader struct {
	name     string
	typeInfo TypeInfo
	metaData MetaData
}

type Headers struct {
	headers []SubHeader
}

func (h *Headers) Write(b []byte) (n int, err error) {
	return 0, errors.New("Unimplemented")
}

// Another tarball
type HeaderSigned struct {
	// data
	data       []byte // TODO - What is in the header?
	headerInfo HeaderInfo
	scripts    Scripts
}

// Another tar-ball
// Augmented header is not signed!
type HeaderAugment struct {
	headerInfo HeaderInfo
	subHeaders []SubHeader
}

func (h *HeaderAugment) Write(b []byte) (n int, err error) {
	// The input is gzipped and tarred, so embed the two
	// readers around the byte stream
	// First wrap the gzip writer
	br := bytes.NewReader(b)
	zr, err := gzip.NewReader(br)
	if err != nil {
		return 0, err
	}
	tr := tar.NewReader(zr)
	hdr, err := tr.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name != "header-info" {
		return 0, fmt.Errorf("Unexpected header: %s", hdr.Name)
	}
	// Read the header info
	if _, err = io.Copy(h.headerInfo, tr); err != nil {
		return 0, nil
	}
	// Read all the headers
	for {
		// hdr.Name is already set, as we broke out of the script parsing loop
		if filepath.Base(hdr.Name) != "type-info" {
			return 0, fmt.Errorf("Expected `type-info`. Got %s", hdr.Name) // TODO - this should probs be a parseError type
		}
		sh := SubHeader{}
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
		h.subHeaders = append(h.subHeaders, sh)
	}
}

type PayLoad struct {
	// Give me morez!
}

func (p PayLoad) Write(b []byte) (n int, err error) {
	gzr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	tr := tar.NewReader(gzr)
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
		_, err = io.Copy(f, tr)
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
type Data struct {
	// Updates 4 all ^^
	payloads []PayLoad
}

func (d *Data) Write(b []byte) (n int, err error) {
	p := PayLoad{}
	_, err = io.Copy(p, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	d.payloads = append(d.payloads, p)
	return len(b), nil
}

type Artifact struct {
	Version         Version
	Manifest        Manifest
	ManifestSig     ManifestSig
	ManifestAugment ManifestAugment
	HeaderTar       HeaderTar
	HeaderAugment   HeaderAugment
	HeaderSigned    HeaderSigned
	Data            Data
}

type Parser struct {
	// The parser
	// lexer *Lexer
}

func (p *Parser) Write(b []byte) (n int, err error) {
	gzr, err := gzip.NewReader(bytes.NewBuffer(b))
	if err != nil {
		return 0, err
	}
	artifact := Artifact{}
	tr = tar.NewReader(gzr)
	// Expect `version`
	hdr, err := tar.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name != "version" {
		return 0, fmt.Errorf("Expected version. Got %s", hdr.Name)
	}
	if _, err = io.Copy(artifact.Version, tr); err != nil {
		return 0, err
	}
	// Expect `manifest`
	hdr, err = tr.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name != "manifest" {
		return 0, fmt.Errorf("Expected `manifest`. Got %s", hdr.Name)
	}
	if _, err = io.Copy(artifact.Manifest); err != nil {
		return 0, err
	}
	// Optional expect `manifest.sig`
	hdr, err := tar.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name == "manifest.sig" {
		if _, err = io.Copy(artifact.ManifestSig, tr); err != nil {
			return 0, err
		}
		// Optional expect `manifest-augment`
		hdr, err = tr.Next()
		if err != nil {
			return 0, err
		}
		if hdr.Name == "manifest-augment" {
			if _, err = io.Copy(artifact.ManifestAugment, tr); err != nil {
				return 0, err
			}
		}
		hdr, err = tr.Next()
		if err != nil {
			return 0, err
		}
	}
	// Expect `header.tar.gz`
	if hdr.Name != "header.tar.gz" {
		return 0, fmt.Errorf("Expected `header.tar.gz`. Got %s", hdr.Name)
	}
	if _, err = io.Copy(artifact.HeaderTar, tr); err != nil {
		return 0, err
	}
	// Optional `header-augment.tar.gz`
	hdr, err = tr.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name == "header-augment.tar.gz" {
		if _, err = io.Copy(artifact.HeaderAugment, tr); err != nil {
			return 0, err
		}
		hdr, err = tr.Next()
		if err != nil {
			return 0, err
		}
	}
	// Expect `data`
	if filepath.Dir(hdr.Name) != "data" {
		return 0, fmt.Errorf("Expected `data`. Got %s", hdr.Name)
	}
	if _, err = io.Copy(artifact.Data, tr); err != nil {
		return 0, err
	}
	return len(b), nil
}

// func New(lexer *Lexer) *Parser {
// 	return Parser{lexer}
// }
