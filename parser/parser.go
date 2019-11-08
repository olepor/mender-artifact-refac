package parser

// TODO's
//
// * Get the checksum whilst parsing the Artifact
// * Get the signature whilst parsing the Artifact
// * Decide upon a structure, and API for moving out of POC
// * Add logging, after deciding on the logger
//

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"crypto/sha256"
	"github.com/pkg/errors"
	"io/ioutil"
	"text/template"

	log "github.com/sirupsen/logrus"
)

func init() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	log.SetLevel(log.TraceLevel)
}

///////////////////////////////////////////////
// Simple parser for the mender-artifact format
///////////////////////////////////////////////

// {
// 	"format": "mender",
// 	"version": 3
// }
type Version struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	shaSum  []byte
}

func (v Version) String() string {
	return fmt.Sprintf("Format:\n\t%s\n"+
		"Version:\n\t%d\nsha:%x\n",
		v.Format,
		v.Version,
		v.shaSum)
}

func (v *Version) Parse(r io.Reader) error {
	if v == nil {
		v = &Version{}
	}
	sha := sha256.New()
	mw := io.MultiWriter(v, sha)
	if _, err := io.Copy(mw, r); err != nil {
		return errors.Wrap(err, "Parser: Write: Failed to read version")
	}
	v.shaSum = sha.Sum(nil)
	return nil
}

// Write Accept the byte body from the tar reader
func (v *Version) Write(b []byte) (n int, err error) {
	log.Debug("Parsing  Version")
	if err = json.Unmarshal(b, v); err != nil {
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

func (m *Manifest) Parse(r io.Reader) error {
	if m == nil {
		m = &Manifest{} /* Allow parsing into an empty value */
	}
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
	return nil
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

func (m *ManifestSig) Parse(r io.Reader) error {
	if m == nil {
		m = &ManifestSig{}
	}
	sig, err := ioutil.ReadAll(r)
	m.sig = sig
	return err

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

func (m *ManifestAugment) Parse(r io.Reader) error {
	if m == nil {
		m = &ManifestAugment{}
	}
	log.Debug("Parsing manifest-augment")
	scanner := bufio.NewScanner(r)
	var line string
	for scanner.Scan() {
		line = scanner.Text()
		tmp := strings.Split(line, " ")
		m.augData = append(m.augData,
			ManifestData{
				Signature: tmp[0],
				Name:      tmp[1]})
	}
	return nil
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
	shaSum     []byte
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
func (h *HeaderTar) Parse(r io.Reader) error {
	if h == nil {
		h = &HeaderTar{} /* TODO -- Maybe set the standard script path here? */
	}
	// The input is gzipped and tarred, so embed the two
	// readers around the byte stream
	// First wrap the gzip writer
	log.Debug("Parsing header.tar")
	sha := sha256.New()
	teeReader := io.TeeReader(r, sha)
	zr, err := gzip.NewReader(teeReader)
	if err != nil {
		return err
	}
	tarElement := tar.NewReader(zr)
	hdr, err := tarElement.Next()
	if err != nil {
		return err
	}
	if hdr.Name != "header-info" {
		return fmt.Errorf("Unexpected header: %s", hdr.Name)
	}
	// Read the header info
	if _, err = io.Copy(h.headerInfo, tarElement); err != nil {
		return err
	}
	// Read all the scripts
	for {
		hdr, err = tarElement.Next()
		if err != nil {
			return err
		}
		if filepath.Dir(hdr.Name) == "headers/0000" { //  && atoi(hdr.Name) { TODO -- fixup
			break // Move on to parsing headers
		}
		if filepath.Dir(hdr.Name) != "scripts" {
			return fmt.Errorf("Expected scripts. Got: %s", hdr.Name)
		}
		if err = h.scripts.Next(filepath.Base(hdr.Name)); err != nil {
			return err
		}
		if _, err = io.Copy(h.scripts, tarElement); err != nil {
			log.Trace("Scripts copy... err")
			return err
		}
	}
	// Read all the headers
	for {
		log.Trace("Reading all the subheaders")
		// hdr.Name is already set, as we broke out of the script parsing loop
		if filepath.Base(hdr.Name) != "type-info" {
			return fmt.Errorf("Expected `type-info`. Got %s", hdr.Name) // TODO - this should probs be a parseError type
		}
		log.Trace("Reading type-info")
		sh := SubHeader{}
		if _, err = io.Copy(sh.typeInfo, tarElement); err != nil {
			return errors.Wrap(err, "HeaderTar")
		}
		hdr, err = tarElement.Next()
		log.Trace("Reading next..")
		log.Trace(hdr, err)
		// Finished reading `header.tar.gz`
		if err == io.EOF {
			log.Trace("subHeader read (EOF): %s\n", sh.String())
			log.Trace(sh.typeInfo)
			h.headers = append(h.headers, sh)
			return nil
		}
		if err != nil {
			return errors.Wrap(err, "HeaderTar: failed to next hdr")
		}
		log.Trace(hdr.Name)
		if filepath.Base(hdr.Name) == "meta-data" {
			_, err = io.Copy(sh.metaData, tarElement)
			log.Trace("Read meta-data")
			if err != nil {
				return errors.Wrap(err, "HeaderTar: meta-data copy error")
			}
			hdr, err = tarElement.Next()
			log.Trace("After meta-data")
			log.Trace(hdr)
			log.Trace(err)
			log.Trace()
			if err == io.EOF {
				log.Trace("EOF after parsing meta-data in header, breaking out")
				break
			} else if err != nil {
				return errors.Wrap(err, "HeaderTar: failed to get next header")
			}
		}
		log.Trace("subHeader read: %s\n", sh.String())
		h.headers = append(h.headers, sh)
	}

	// Extract the checksum from buf
	h.shaSum = sha.Sum(nil)
	log.Trace("Header.tar.gz - shasum: %x\n", h.shaSum)
	return nil
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
	Type             string           `json:"type"`
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
	log.Debug("Parsing header-augment.tar")
	// The input is gzipped and tarred, so embed the two
	// readers around the byte stream
	// First wrap the gzip writer
	br := bytes.NewReader(b)
	zr, err := gzip.NewReader(br)
	if err != nil {
		return 0, err
	}
	tarElement := tar.NewReader(zr)
	hdr, err := tarElement.Next()
	if err != nil {
		return 0, err
	}
	if hdr.Name != "header-info" {
		return 0, fmt.Errorf("Unexpected header: %s", hdr.Name)
	}
	// Read the header info
	if _, err = io.Copy(h.headerInfo, tarElement); err != nil {
		return 0, nil
	}
	// Read all the headers
	for {
		// hdr.Name is already set, as we broke out of the script parsing loop
		if filepath.Base(hdr.Name) != "type-info" {
			return 0, fmt.Errorf("Expected `type-info`. Got %s", hdr.Name) // TODO - this should probs be a parseError type
		}
		sh := SubHeader{}
		if _, err = io.Copy(sh.typeInfo, tarElement); err != nil {
			return 0, err
		}
		hdr, err = tarElement.Next()
		if err != nil {
			return 0, err
		}
		if filepath.Base(hdr.Name) == "meta-data" {
			_, err = io.Copy(sh.metaData, tarElement)
			if err != nil {
				return 0, err
			}
			hdr, err = tarElement.Next()
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
	log.Trace("len(b): %d\n", len(b))
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
	Version         *Version
	Manifest        *Manifest
	ManifestSig     *ManifestSig
	ManifestAugment *ManifestAugment
	HeaderTar       *HeaderTar
	HeaderAugment   *HeaderAugment
	HeaderSigned    *HeaderSigned
	Data            *Data
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
		// Version:         Version{},
		// Manifest:        Manifest{},
		// ManifestSig:     ManifestSig{},
		// ManifestAugment: ManifestAugment{},
		HeaderTar: &HeaderTar{
			scripts: &Scripts{
				scriptDir: "/Users/olepor/go/src/github.com/olepor/ma-go/scripts", // TODO - make this configureable
			},
		},
		// HeaderAugment: HeaderAugment{},
		// HeaderSigned:  HeaderSigned{},
		// Data:          Data{},
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
	err = p.Parse(r)
	if err != nil {
		return nil, err
	}
	a.p = &p
	a.Artifact = p.artifact

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

func (ar *ArtifactReader) Next() (io.Reader, error) {
	return ar.p.Next()
}

// Parser parses a mender-artifact
type Parser struct {
	// The parser
	// lexer *Lexer
	artifact   Artifact
	tarElement *tar.Reader
}

// Write parses an aritfact from the bytes it is fed.
// TODO -- Change to parse method
func (p *Parser) Parse(r io.Reader) error {
	log.Debug("Parsing Artifact...")
	artifact := New()
	tarElement := tar.NewReader(r)
	p.tarElement = tarElement
	// Expect `version`
	hdr, err := tarElement.Next()
	if err != nil {
		return err
	}
	if hdr.Name != "version" {
		return fmt.Errorf("Expected version. Got %s", hdr.Name)
	}
	if err = artifact.Version.Parse(tarElement); err != nil {
		return fmt.Errorf("Failed to parse the Version header, error: %v", err)
	}
	log.Trace("Parsed version")
	log.Trace(artifact.Version)
	// Expect `manifest`
	hdr, err = tarElement.Next()
	if err != nil {
		return err
	}
	if hdr.Name != "manifest" {
		return fmt.Errorf("Expected `manifest`. Got %s", hdr.Name)
	}
	if err = artifact.Manifest.Parse(tarElement); err != nil {
		return fmt.Errorf("Failed to parse the Manifest header. Error: %v", err)
	}
	log.Trace("Parsed manifest")
	log.Trace(artifact.Manifest)
	// Optional expect `manifest.sig`
	hdr, err = tarElement.Next()
	if err != nil {
		return err
	}
	log.Trace("hdr.Name: %s\n", hdr.Name)
	if hdr.Name == "manifest.sig" {
		log.Trace("Parsing manifest.sig")
		if err = artifact.ManifestSig.Parse(tarElement); err != nil {
			return fmt.Errorf("Failed to parse the Manifest signature. Error: %v", err)
		}
		log.Trace("Parsed manifest.sig")
		log.Trace(artifact.ManifestSig)
		// Optional expect `manifest-augment`
		hdr, err = tarElement.Next()
		if err != nil {
			return err
		}
		if hdr.Name == "manifest-augment" {
			if err = artifact.ManifestAugment.Parse(tarElement); err != nil {
				return fmt.Errorf("Failed to parse 'manifest-augment'. Error: %v", err)
			}
		}
		log.Trace("Parsed manifest-augment")
		hdr, err = tarElement.Next()
		if err != nil {
			return err
		}
	}
	// Expect `header.tar.gz`
	if hdr.Name != "header.tar.gz" {
		return fmt.Errorf("Expected `header.tar.gz`. Got %s", hdr.Name)
	}
	if err = artifact.HeaderTar.Parse(tarElement); err != nil {
		log.Trace("Error parsing header.tar.gz")
		log.Trace(err)
		return err
	}
	log.Trace("Parsed header.tar.gz")
	log.Trace(artifact.HeaderTar)
	// Optional `header-augment.tar.gz`
	hdr, err = tarElement.Next()
	if err != nil {
		return err
	}
	if hdr.Name == "header-augment.tar.gz" {
		if _, err = io.Copy(artifact.HeaderAugment, tarElement); err != nil {
			return err
		}
		log.Trace("Parsed header-augment")
		hdr, err = tarElement.Next()
		if err != nil {
			return err
		}
	}
	// Need call next on `artifact`
	// Expect `data`
	log.Trace("Ready to read `Data`")
	if filepath.Dir(hdr.Name) != "data" {
		return fmt.Errorf("Expected `data`. Got %s", hdr.Name)
	}
	log.Trace("Data hdr: %s\n", hdr.Name)
	log.Trace("Read all initial data, preparing to return Payloads\n")

	return nil
}

type PayloadReader struct {
	tarElement *tar.Reader
}

func (p *PayloadReader) Read(b []byte) (n int, err error) {
	// sha := sha256.New()
	// tr := io.TeeReader(p.tarElement, sha)
	return 0, nil

}

// Next returns the next payload in an artifact
func (p *Parser) Next() (io.Reader, error) {
	// Unzip the data/0000.tar.gz file
	compressedReader, err := gzip.NewReader(p.tarElement)
	if err != nil {
		log.Trace("Failed to open a gzip reader for the artifact")
		// return 0, err
		return nil, err
	}
	// data/0000.tar
	pr := tar.NewReader(compressedReader)
	hdr, err := pr.Next()
	if err != nil {
		return nil, fmt.Errorf("Failed to get the tar info in 'data/0000.tar', Error: %v", err)
	}
	log.Trace("Payload name: ")
	log.Trace(hdr.Name)
	// Write the payload to stdout
	// io.Copy(os.Stdout, pr)
	return pr, nil
}

// Read - Creates an artifact from the underlying artifact struct
func (p *Parser) Read(b []byte) (n int, err error) {
	return 0, errors.New("Unimplemented")
}
