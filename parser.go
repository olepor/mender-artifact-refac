package parser

// Simple parser for the mender-artifact format

// This needs to be parsed from 'json'
type version struct {
	format  string
	version int
}

// The signature for the manifest
type manifestData struct {
	signature []byte
	name      string
}

type manifest struct {
	data []manifestData
}

type manifestSig struct {
	// More data
	sig []byte
}

type manifestAugment struct {
	// Some Data 4 deltaz
	augData []byte
}

type headerInfo struct {
	// Dataz
	data []byte
}

// All the Artifact scripts
type scripts struct {
	scrpts []string
}

type typeInfo struct {
	// type-info
}

type metaData struct {
	// meta-data
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
	typeInfo typeInfo
	metaData metaData
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


type payLoad struct {
	// Give me morez!
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

type Parser struct {
	// The parser
	lexer *Lexer
}

func New(lexer *Lexer) *Parser {
	return Parser{lexer}
}
