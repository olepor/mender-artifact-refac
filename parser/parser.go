package parser

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

///////////////////////////////////////////////
// Simple parser for the mender-artifact format
///////////////////////////////////////////////

// {
// 	"format": "mender",
// 	"version": 3
// }
type Version struct {
	Format  string `json:"format"`
	Version int    `json:"version`
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
	for scanner.Scan() {
		line = scanner.Text()
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
	for scanner.Scan() {
		line = scanner.Text()
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
	scripts    *Scripts
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
	fmt.Println("Ready to read to header info")
	if _, err = io.Copy(h.headerInfo, tr); err != nil {
		return 0, err
	}
	fmt.Println("HeaderTar: Read headerInfo")
	// Read all the scripts
	for {
		hdr, err = tr.Next()
		if err != nil {
			return 0, err
		}
		fmt.Printf("Write script: %s\n", hdr.Name)
		if filepath.Dir(hdr.Name) == "headers/0000" { //  && atoi(hdr.Name) { TODO -- fixup
			fmt.Println("Moving on to reading headers...")
			break // Move on to parsing headers
		}
		if filepath.Dir(hdr.Name) != "scripts" {
			return 0, fmt.Errorf("Expected scripts. Got: %s", hdr.Name)
		}
		fmt.Println("scripts.Next")
		if err = h.scripts.Next(filepath.Base(hdr.Name)); err != nil {
			return 0, err
		}
		fmt.Println("scripts.Write")
		if _, err = io.Copy(h.scripts, tr); err != nil {
			fmt.Println("Scripts copy... err")
			return 0, err
		}

	}
	fmt.Println("Finished reading scripts...")
	// Read all the headers
	for {
		// hdr.Name is already set, as we broke out of the script parsing loop
		if filepath.Base(hdr.Name) != "type-info" {
			return 0, fmt.Errorf("Expected `type-info`. Got %s", hdr.Name) // TODO - this should probs be a parseError type
		}
		sh := SubHeader{}
		if _, err = io.Copy(sh.typeInfo, tr); err != nil {
			return 0, errors.Wrap(err, "HeaderTar")
		}
		hdr, err = tr.Next()
		// Finished reading `header.tar.gz`
		if err == io.EOF {
			h.headers = append(h.headers, sh)
			return len(b), nil
		}
		if err != nil {
			return 0, errors.Wrap(err, "HeaderTar: failed to next hdr")
		}
		if filepath.Base(hdr.Name) == "meta-data" {
			_, err = io.Copy(sh.metaData, tr)
			if err != nil {
				return 0, errors.Wrap(err, "HeaderTar: meta-data copy error")
			}
			hdr, err = tr.Next()
			if err != nil {
				return 0, errors.Wrap(err, "HeaderTar: failed to get next header")
			}
		}
		h.headers = append(h.headers, sh)
	}
}

type Payload struct {
	Type string `json:"type"`
}

type ArtifactProvides struct {
	ArtifactName  string `json:"artifact_name"`
	ArtifactGroup string `json:"artifact_group"`
}

type ArtifactDepends struct {
	ArtifactName []string `json:"artifact_name"`
	DeviceType   []string `json:"device_type"`
}

type HeaderInfo struct {
	// Dataz
	Payloads         []Payload        `json:"payloads"`
	ArtifactProvides ArtifactProvides `json:"artifact_provides"`
	ArtifactDepends  ArtifactDepends  `json:"artifact_depends"`
}

func (h HeaderInfo) Write(b []byte) (n int, err error) {
	err = json.Unmarshal(b, &h)
	if err != nil {
		return 0, err
	}
	fmt.Printf("HeaderInfo: Write: headerInfo: %v\n", h)
	return len(b), nil
}

// All the Artifact scripts
type script struct {
	// Identity
}

type Scripts struct {
	scriptDir         string // configureable
	currentScriptName string
	file              *os.File
}

func (s *Scripts) Next(filename string) error {
	fmt.Printf("Scripts Next .\n")
	f, err := os.Create(filepath.Join(s.scriptDir, filename))
	if err != nil {
		fmt.Printf("Scripts: Next, error: %s\n", err.Error())
		return err
	}
	s.file = f
	return nil
}

// The scripts Write reads a file from the byte stream
// and writes it to /scripts/<ScriptName>
func (s Scripts) Write(b []byte) (n int, err error) {
	fmt.Println("Scripts Write function")
	if s.file == nil {
		return 0, fmt.Errorf("Next must be called, prior to writing a script")
	}
	_, err = io.Copy(s.file, bytes.NewReader(b))
	return len(b), err
}

type TypeInfoProvides struct {
	RootfsImageChecksum string `json:"rootfs_image_checksum"`
}

type TypeInfoDepends struct {
	RootfsImageChecksum string `json:"rootfs_image_checksum"`
}

type TypeInfo struct {
	Type             string           `json"type"`
	TypeInfoProvides TypeInfoProvides `json:"artifact_provides"`
	TypeInfoDepends  TypeInfoDepends  `json:"artifact_depends"`
}

func (t TypeInfo) Write(b []byte) (n int, err error) {
	err = json.Unmarshal(b, &t)
	if err != nil {
		return 0, errors.Wrap(err, "TypeInfo: Write: Failed to unmarshal json")
	}
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

type PayLoadData struct {
	// Give me morez!
	Name string
	Data bytes.Buffer
}

func (p *PayLoadData) Write(b []byte) (n int, err error) {
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return len(b), nil
		}
		if err != nil {
			return 0, errors.Wrap(err, "Payload: Write: Tar failed to produce the next header")
		}
		p.Name = hdr.Name
		fmt.Printf("Payload name: %s\n", hdr.Name)
		for {
			trs := tar.NewReader(tr)
			shdr, err := trs.Next()
			if err == io.EOF {
				break // Drained sub-tar
			}
			if err != nil {
				return 0, errors.Wrap(err, "Payload: Write: Failed to extract")
			}
			if hdr.Typeflag != tar.TypeDir {
				fmt.Printf("sub-tar: Name: %s\n", shdr.Name)
				fmt.Printf("sub-tar: Info: %v\n", shdr)
				n, err := io.Copy(ioutil.Discard, trs)
				if err != nil {
					return 0, errors.Wrapf(err,
						"Payload: Write: Failed to buffer the update. Written: %d expected: %d", n, shdr.Size)
				}
			}
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
	payloads []PayLoadData
}

func (d *Data) Write(b []byte) (n int, err error) {
	fmt.Printf("len(b): %d\n", len(b))
	gzipr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return 0, errors.Wrap(err, "Data: Write: Failed to unzip the Payload")
	}
	pl := &PayLoadData{}
	_, err = io.Copy(pl, gzipr)
	if err != nil {
		return 0, errors.Wrap(err, "Data: Write: Failed to write the payload struct")
	}
	return len(b), nil
}

type Artifact struct {
	Version         *Version
	Manifest        *Manifest
	ManifestSig     *ManifestSig
	ManifestAugment *ManifestAugment
	HeaderTar       *HeaderTar
	HeaderAugment   *HeaderAugment
	HeaderSigned    *HeaderSigned
	Data            *Data
}

// New returns an instantiated basic artifact, ready for parsing
func New() *Artifact {
	return &Artifact{
		Version:         &Version{},
		Manifest:        &Manifest{},
		ManifestSig:     &ManifestSig{},
		ManifestAugment: &ManifestAugment{},
		HeaderTar: &HeaderTar{
			scripts: &Scripts{
				scriptDir: "/Users/olepor/go/src/github.com/olepor/ma-go/scripts", // TODO - make this configureable
			},
		},
		HeaderAugment: &HeaderAugment{},
		HeaderSigned:  &HeaderSigned{},
		Data:          &Data{},
	}
}

type Parser struct {
	// The parser
	// lexer *Lexer
}

func (p *Parser) Write(b []byte) (n int, err error) {
	var compressedReader io.Reader
	compressedReader, err = gzip.NewReader(bytes.NewBuffer(b))
	if err != nil {
		fmt.Println("Failed to open a gzip reader for the artifact")
		// return 0, err
		compressedReader = bytes.NewReader(b) // Let's try N see if it is not compressed
	}
	artifact := New()
	tr := tar.NewReader(compressedReader)
	// Expect `version`
	hdr, err := tr.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name != "version" {
		return 0, fmt.Errorf("Expected version. Got %s", hdr.Name)
	}
	if _, err = io.Copy(artifact.Version, tr); err != nil {
		return 0, errors.Wrap(err, "Parser: Write: Failed to read version")
	}
	fmt.Println("Parsed version")
	// Expect `manifest`
	hdr, err = tr.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name != "manifest" {
		return 0, fmt.Errorf("Expected `manifest`. Got %s", hdr.Name)
	}
	if _, err = io.Copy(artifact.Manifest, tr); err != nil {
		return 0, err
	}
	fmt.Println("Parsed manifest")
	// Optional expect `manifest.sig`
	hdr, err = tr.Next()
	if err != nil {
		return 0, err
	}
	fmt.Printf("hdr.Name: %s\n", hdr.Name)
	if hdr.Name == "manifest.sig" {
		fmt.Println("Parsing manifest.sig")
		if _, err = io.Copy(artifact.ManifestSig, tr); err != nil {
			return 0, err
		}
		fmt.Println("Parsed manifest.sig")
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
		fmt.Println("Parsed manifest-augment")
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
	fmt.Println("Parsed header.tar.gz")
	// Optional `header-augment.tar.gz`
	hdr, err = tr.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name == "header-augment.tar.gz" {
		if _, err = io.Copy(artifact.HeaderAugment, tr); err != nil {
			return 0, err
		}
		fmt.Println("Parsed header-augment")
		hdr, err = tr.Next()
		if err != nil {
			return 0, err
		}
	}
	// Expect `data`
	fmt.Println("Ready to read `Data`")
	if filepath.Dir(hdr.Name) != "data" {
		return 0, fmt.Errorf("Expected `data`. Got %s", hdr.Name)
	}
	fmt.Printf("Data hdr: %s\n", hdr.Name)
	for {
		_, err = io.Copy(artifact.Data, tr)
		if err != nil {
			return 0, errors.Wrap(err, "Parser: Writer: Failed to read the payload")
		}
		hdr, err = tr.Next()
		if err == io.EOF {
			return len(b), nil
		}
		if err != nil {
			return 0, errors.Wrap(err, "Parser: Failed to empty tar")
		}
	}
	fmt.Println("Done! \\o/")
	return len(b), nil
}

// func New(lexer *Lexer) *Parser {
// 	return Parser{lexer}
// }
