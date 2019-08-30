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

	"github.com/alecthomas/template"
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

func (v Version) String() string {
	return fmt.Sprintf("Format:\n\t%s\n"+
		"Version:\n\t%d\n",
		v.Format,
		v.Version)
}

// Accept the byte body from the tar reader
func (v *Version) Write(b []byte) (n int, err error) {
	if err := json.Unmarshal(b, v); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read Creates an artifact Version
func (v *Version) Read(b []byte) (n int, err error) {
	if b, err = json.Marshal(v); err != nil {
		return 0, errors.Wrap(err, "Version: Read: Failed to marshal json")
	}
	return len(b), nil
}

// The signature for the manifest
// 5ac394718e795d454941487c53d32  data/0000/update.ext4
// b7793eb1c57c4694532f96383b619  header.tar.gz
// a343fec7ba3b2983c2ecbbb041a35  version
type ManifestData struct {
	Signature string
	Name      string
}

type Manifest struct {
	Data []ManifestData
}

func (m Manifest) String() string {
	buf := bytes.NewBuffer(nil)
	buf.WriteString("Signature:        FileName:\n")
	for _, data := range m.Data {
		fmt.Fprintf(buf, "%10s\t\t%s\n", data.Signature, data.Name)
	}
	return buf.String()
}

func (m *Manifest) Write(b []byte) (n int, err error) {
	r := bytes.NewBuffer(b)
	scanner := bufio.NewScanner(r)
	var line string
	for scanner.Scan() {
		line = scanner.Text()
		tmp := strings.Split(line, " ")
		m.Data = append(m.Data,
			ManifestData{
				Signature: tmp[0],
				Name:      tmp[2]})
	}
	return len(b), nil
}

func (m *Manifest) Read(b []byte) (n int, err error) {
	br := bytes.NewBuffer(nil)
	for _, manifestData := range m.Data {
		line := manifestData.Signature + " " + manifestData.Name + "\n"
		_, err = br.Write([]byte(line))
		if err != nil {
			return 0, errors.Wrap(err, "Manifest: Read: Failed to write line")
		}
	}
	b = br.Bytes()
	return len(b), nil
}

// Format: base64 encoded ecdsa or rsa signature
type ManifestSig struct {
	// More data
	sig []byte
}

func (m *ManifestSig) String() string {
	return fmt.Sprintf("Manifest Signature: %x", m.sig)
}

func (m *ManifestSig) Write(b []byte) (n int, err error) {
	m.sig = b
	return len(b), nil
}

func (m *ManifestSig) Read(b []byte) (n int, err error) {
	b = m.sig
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
				Signature: tmp[0],
				Name:      tmp[1]})
	}
	return len(b), nil
}

func (m *ManifestAugment) Read(b []byte) (n int, err error) {
	br := bytes.NewBuffer(nil)
	for _, maugData := range m.augData {
		line := maugData.Signature + " " + maugData.Name + "\n"
		_, err = br.Write([]byte(line))
		if err != nil {
			return 0, errors.Wrap(err,
				"ManifestAugment: Read: Failed to write to byte buffer")
		}
	}
	b = br.Bytes()
	return len(b), nil
}

type HeaderTar struct {
	headerInfo HeaderInfo
	scripts    *Scripts
	headers    []SubHeader
}

func (h HeaderTar) String() string {
	s := bytes.NewBuffer(nil)
	s.WriteString("Scripts: " + h.scripts.String())
	for _, header := range h.headers {
		s.WriteString(header.String())
	}
	return s.String()
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
		return 0, err
	}
	// Read all the scripts
	for {
		hdr, err = tr.Next()
		if err != nil {
			return 0, err
		}
		if filepath.Dir(hdr.Name) == "headers/0000" { //  && atoi(hdr.Name) { TODO -- fixup
			break // Move on to parsing headers
		}
		if filepath.Dir(hdr.Name) != "scripts" {
			return 0, fmt.Errorf("Expected scripts. Got: %s", hdr.Name)
		}
		if err = h.scripts.Next(filepath.Base(hdr.Name)); err != nil {
			return 0, err
		}
		if _, err = io.Copy(h.scripts, tr); err != nil {
			fmt.Println("Scripts copy... err")
			return 0, err
		}
	}
	// Read all the headers
	for {
		fmt.Println("Reading all the subheaders")
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
			fmt.Printf("subHeader read (EOF): %s\n", sh.String())
			fmt.Println(sh.typeInfo)
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
		fmt.Printf("subHeader read: %s\n", sh.String())
		h.headers = append(h.headers, sh)
	}
}

func (h *HeaderTar) Read(b []byte) (n int, err error) {
	return 0, errors.New("Unimplemented")
}

type Payload struct {
	Type string `json:"type"`
}

func (p Payload) String() string {
	return p.Type
}

type ArtifactProvides struct {
	ArtifactName  string `json:"artifact_name"`
	ArtifactGroup string `json:"artifact_group"`
}

func (a ArtifactProvides) String() string {
	return fmt.Sprintf("ArtifactName: %s\nArtifactGroup:%s\n", a.ArtifactName, a.ArtifactGroup)
}

type ArtifactDepends struct {
	ArtifactName []string `json:"artifact_name"`
	DeviceType   []string `json:"device_type"`
}

func (a ArtifactDepends) String() string {
	return fmt.Sprintf("ArtifactName: %s\nDeviceType:%s\n", a.ArtifactName, a.DeviceType)
}

type HeaderInfo struct {
	// Dataz
	Payloads         []Payload        `json:"payloads"`
	ArtifactProvides ArtifactProvides `json:"artifact_provides"`
	ArtifactDepends  ArtifactDepends  `json:"artifact_depends"`
}

func (h HeaderInfo) String() string {
	buf := bytes.NewBuffer(nil)
	for _, payload := range h.Payloads {
		fmt.Fprintf(buf, "Payload: %s\n", payload.String())
	}
	fmt.Fprintf(buf, "ArtifactProvides:\n\t%s", h.ArtifactProvides)
	fmt.Fprintf(buf, "ArtifactDepends:\n\t%s", h.ArtifactProvides)
	return buf.String()
}

func (h HeaderInfo) Write(b []byte) (n int, err error) {
	err = json.Unmarshal(b, &h)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (h *HeaderInfo) Read(b []byte) (n int, err error) {
	b, err = json.Marshal(h)
	if err != nil {
		return 0, errors.Wrap(err, "HeaderInfo: Read: Failed to marshal json")
	}
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
	names             []string
}

func (s *Scripts) String() string {
	buf := bytes.NewBuffer(nil)
	for _, name := range s.names {
		fmt.Fprintf(buf, "\n\t%s", name)
	}
	fmt.Fprintln(buf)
	return buf.String()
}

func (s *Scripts) Next(filename string) error {
	f, err := os.Create(filepath.Join(s.scriptDir, filename))
	if err != nil {
		return err
	}
	s.file = f
	s.names = append(s.names, filepath.Join(s.scriptDir, filename))
	return nil
}

// The scripts Write reads a file from the byte stream
// and writes it to /scripts/<ScriptName>
func (s Scripts) Write(b []byte) (n int, err error) {
	if s.file == nil {
		return 0, fmt.Errorf("Next must be called, prior to writing a script")
	}
	_, err = io.Copy(s.file, bytes.NewReader(b))
	return len(b), err
}

func (s Scripts) Read(b []byte) (n int, err error) {
	return 0, errors.New("Unimplemented")
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

func (t TypeInfo) String() string {
	typeinfotmplstr := `{{ if .Type}} {{ printf "%s" .Type }} {{ end }}
{{ if .TypeInfoProvides}} {{ printf "%s" .TypeInfoProvides }} {{ end }}
{{ if .TypeInfoDepends}} {{ printf "%s" .TypeInfoDepends }} {{ end }}`
	typeinfotmpl, err := template.New("master").Parse(typeinfotmplstr)
	if err != nil {
		panic("Failed to create the template for TypeInfo")
	}
	buf := bytes.NewBuffer(nil)
	if err := typeinfotmpl.Execute(buf, t); err != nil {
		panic("Failed to write the template for TypeInfo")
	}
	return buf.String()
}

func (t TypeInfo) Write(b []byte) (n int, err error) {
	err = json.Unmarshal(b, &t)
	if err != nil {
		return 0, errors.Wrap(err, "TypeInfo: Write: Failed to unmarshal json")
	}
	return len(b), err
}

func (t TypeInfo) Read(b []byte) (n int, err error) {
	b, err = json.Marshal(&t)
	if err != nil {
		return 0, errors.Wrap(err, "TypeInfo: Read: Failed to marshal json")
	}
	return len(b), nil
}

type MetaData struct {
	// meta-data
}

func (m MetaData) String() string {
	return ""
}

func (t MetaData) Write(b []byte) (n int, err error) {
	_, err = io.Copy(ioutil.Discard, bytes.NewReader(b))
	return len(b), err
}

func (t MetaData) Read(b []byte) (n int, err error) {
	return 0, errors.New("Unimplemented")
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

func (s *SubHeader) String() string {
	return fmt.Sprintf("Name: %s\nTypeInfo: %s\nMetaData: %s\n", s.name, s.typeInfo, s.metaData)
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

func (h *HeaderAugment) Read(b []byte) (n int, err error) {
	return 0, errors.New("Unimplemented")
}

type PayLoadData struct {
	// Give me morez!
	Name    string
	Data    bytes.Buffer
	OutData io.Reader
	Update  io.Reader
}

func (p *PayLoadData) Write(b []byte) (n int, err error) {
	// Wrap the update in a reader to expose it to the outside world
	p.OutData = bytes.NewBuffer(b)
	return len(b), nil
}

func (p *PayLoadData) Read(b []byte) (n int, err error) {
	// Read from the underlying update files to the payload
	buf := bytes.NewBuffer(b)
	_, err = io.Copy(buf, p.Update)
	if err != nil {
		return 0, errors.Wrap(err, "PayloadData: Read")
	}
	b = buf.Bytes()
	return len(b), nil
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

func (d *Data) Read(b []byte) (n int, err error) {
	// Simply gzip and write the data to make it pretty for the tar-writer
	buf := bytes.NewBuffer(nil)
	gzw := gzip.NewWriter(buf)
	for _, payload := range d.payloads {
		_, err = io.Copy(gzw, &payload)
		if err != nil {
			return 0, errors.Wrap(err, "Data: Read")
		}
	}
	b = buf.Bytes()
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

func (a *Artifact) String() string {
	return fmt.Sprintf("Version:\n\t%s"+
		"Manifest:\n\t%s"+
		"ManifestSig:\n\t%s"+
		"ManifestAugment:\n\t%s"+
		"HeaderTar:\n\t%s"+
		"HeaderAugment:\n\t%s"+
		"HeaderSigned:\n\t%s"+
		"Data:\n\t%s",
		a.Version,
		a.Manifest,
		a.ManifestSig,
		a.ManifestAugment,
		a.HeaderTar,
		a.HeaderAugment,
		a.HeaderSigned,
		a.Data)
}

// New returns an instantiated basic artifact, ready for parsing
func New() *Artifact {
	return &Artifact{
		Version:         Version{},
		Manifest:        Manifest{},
		ManifestSig:     ManifestSig{},
		ManifestAugment: ManifestAugment{},
		HeaderTar: HeaderTar{
			scripts: &Scripts{
				scriptDir: "/Users/olepor/go/src/github.com/olepor/ma-go/scripts", // TODO - make this configureable
			},
		},
		HeaderAugment: HeaderAugment{},
		HeaderSigned:  HeaderSigned{},
		Data:          Data{},
	}
}

// ArtifactReader wraps a reader, and parses it into an artifact
type ArtifactReader struct {
	r        io.Reader
	p        *Parser
	Artifact Artifact
}

func NewArtifactReader() *ArtifactReader {
	return &ArtifactReader{}
}

func (a *ArtifactReader) Parse(r io.Reader) (ar *Artifact, err error) {
	p := Parser{}
	io.Copy(&p, r)

	return &p.artifact, nil
	// return &Artifact{
	// 	Version:         Version{},
	// 	Manifest:        Manifest{},
	// 	ManifestSig:     ManifestSig{},
	// 	ManifestAugment: ManifestAugment{},
	// 	HeaderTar: HeaderTar{
	// 		scripts: &Scripts{
	// 			scriptDir: "/Users/olepor/go/src/github.com/olepor/ma-go/scripts", // TODO - make this configureable
	// 		},
	// 	},
	// 	HeaderAugment: HeaderAugment{},
	// 	HeaderSigned:  HeaderSigned{},
	// 	Data:          Data{},
	// }, nil
}

func (ar *ArtifactReader) Next() (*PayLoadData, error) {
	return ar.p.Next()
}

// Parser parses a mender-artifact
type Parser struct {
	// The parser
	// lexer *Lexer
	artifact Artifact
	tr       *tar.Reader
}

// Write parses an aritfact from the bytes it is fed.
func (p *Parser) Write(b []byte) (n int, err error) {
	var compressedReader io.Reader
	buf := bytes.NewBuffer(b)
	compressedReader, err = gzip.NewReader(buf)
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
	if _, err = io.Copy(&artifact.Version, tr); err != nil {
		return 0, errors.Wrap(err, "Parser: Write: Failed to read version")
	}
	fmt.Println("Parsed version")
	fmt.Println(artifact.Version)
	// Expect `manifest`
	hdr, err = tr.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name != "manifest" {
		return 0, fmt.Errorf("Expected `manifest`. Got %s", hdr.Name)
	}
	if _, err = io.Copy(&artifact.Manifest, tr); err != nil {
		return 0, err
	}
	fmt.Println("Parsed manifest")
	fmt.Println(artifact.Manifest)
	// Optional expect `manifest.sig`
	hdr, err = tr.Next()
	if err != nil {
		return 0, err
	}
	fmt.Printf("hdr.Name: %s\n", hdr.Name)
	if hdr.Name == "manifest.sig" {
		fmt.Println("Parsing manifest.sig")
		if _, err = io.Copy(&artifact.ManifestSig, tr); err != nil {
			return 0, err
		}
		fmt.Println("Parsed manifest.sig")
		fmt.Println(artifact.ManifestSig)
		// Optional expect `manifest-augment`
		hdr, err = tr.Next()
		if err != nil {
			return 0, err
		}
		if hdr.Name == "manifest-augment" {
			if _, err = io.Copy(&artifact.ManifestAugment, tr); err != nil {
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
	if _, err = io.Copy(&artifact.HeaderTar, tr); err != nil {
		return 0, err
	}
	fmt.Println("Parsed header.tar.gz")
	fmt.Println(artifact.HeaderTar)
	// Optional `header-augment.tar.gz`
	hdr, err = tr.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name == "header-augment.tar.gz" {
		if _, err = io.Copy(&artifact.HeaderAugment, tr); err != nil {
			return 0, err
		}
		fmt.Println("Parsed header-augment")
		hdr, err = tr.Next()
		if err != nil {
			return 0, err
		}
	}
	// Need call next on `artifact`
	// Expect `data`
	// fmt.Println("Ready to read `Data`")
	// if filepath.Dir(hdr.Name) != "data" {
	// 	return 0, fmt.Errorf("Expected `data`. Got %s", hdr.Name)
	// }
	// fmt.Printf("Data hdr: %s\n", hdr.Name)
	// fmt.Printf("Read all initial data, preparing to return Payloads\n")
	// // Store the necessary resources
	// p.artifact = artifact
	// p.tr = tr
	return buf.Len(), nil // TODO -- Which length to return (?)
}

// Next returns the next payload in an artifact
func (p *Parser) Next() (*PayLoadData, error) {
	tr := p.tr
	hdr, err := tr.Next()
	payload := &PayLoadData{}
	nr, err := io.Copy(payload, tr)
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, errors.Wrap(err, fmt.Sprintf("Parser: Writer: Failed to read the payload: Written: %d, Expected: %d", nr, hdr.Size))
	}
	return payload, nil
}

// Read - Creates an artifact from the underlying artifact struct
func (p *Parser) Read(b []byte) (n int, err error) {
	return 0, errors.New("Unimplemented")
}
