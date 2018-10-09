package lib

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"text/template"
)

// Config holds the settings chosen by the user
type Config struct {
	Language       string        `yaml:"language"`
	PayloadFile    string        `yaml:"payloadFile"`
	OutputFile     string        `yaml:"outputFile"`
	Keyers         []ConfigKeyer `yaml:"keyers"`
	Retries        string        `yaml:"retries"`
	Sleep          string        `yaml:"sleep"`
	DisableNesting bool          `yaml:"disableNesting"`
	BaseCode       string        `yaml:"baseCode"`
	// Used for C# payloads
	AssemblyType   string        `yaml:"assemblyType"`
	AssemblyMethod string        `yaml:"assemblyMethod"`
}

// ConfigKeyer stores keyer options provided within a config file
type ConfigKeyer struct {
	Name   string   `yaml:"name"`
	Inputs []string `yaml:"inputs"`
	Output string   `yaml:"keydata"`
}

// Language object stores basic info for each language
// This data will come from the lang.xml file in the root
// directory of the language's directory
type Language struct {
	Name      string `xml:"name"`
	Extension string `xml:"extension"`
	BaseCode  string `xml:"baseCode"`
}

// Keyer stores information related to each keyer:
//     Name: name of the keyer
//     Description: brief description of the keyer
//     Type: the type of keyer: combo or chain
//     InputNum: number of inputs that need to be provided from user
//     Function: primary function that will be called to return something to
//				 use as a part of the decryption key
//     Caller: additional code that will call the function and append to the
//             relevant array to eventually build the decryption key
type Keyer struct {
	Name        string
	Title       string `xml:"title"`
	Description string `xml:"description"`
	Type        string `xml:"type"`
	InputNum    int    `xml:"inputnum"`
	InputHelp   string `xml:"inputhelp"`
	Function    string `xml:"function"`
	Caller      string `xml:"caller"`
}

//
// Code Section functions
//

// ParseLanguage takes a given language, finds the filename and returns the Language struct
func ParseLanguage(lang string) (Language, error) {
	langFile := fmt.Sprintf("./data/%s/lang.xml", lang)
	langBytes, err := ReadFile(langFile)
	if err != nil {
		return Language{}, err
	}

	var l Language
	xml.Unmarshal(langBytes, &l)
	return l, nil
}

// ParseKeyer takes a given language and keyer name, appends '.xml' then calls ParseKeyerFile
func ParseKeyer(lang, keyer string) (Keyer, error) {
	keyer = keyer + ".xml"
	return ParseKeyerFile(lang, keyer)
}

// ParseKeyerFile takes a given language and keyer filename, then returns the Keyer struct
func ParseKeyerFile(lang, keyerFileName string) (Keyer, error) {
	keyerFile := fmt.Sprintf("./data/%s/keyers/%s", lang, keyerFileName)
	keyerBytes, err := ReadFile(keyerFile)
	if err != nil {
		return Keyer{}, err
	}

	var k Keyer
	k.Name = strings.TrimSuffix(keyerFileName, ".xml")
	xml.Unmarshal(keyerBytes, &k)
	return k, nil
}

// GetLanguages returns all the langs based on directories in ./data
func GetLanguages() []string {
	items, err := ioutil.ReadDir("./data")
	if err != nil {
		fmt.Printf("[!] Error reading folders under ./data: %s\n", err)
		return nil
	}

	var langs []string
	for _, item := range items {
		if item.IsDir() {
			langs = append(langs, item.Name())
		}
	}

	return langs
}

// GetCodeFiles gets all xml files under the specified code section directory
func GetCodeFiles(lang, section string) []string {
	ext := ".xml"

	folderPath := fmt.Sprintf("./data/%s/%s/", lang, section)
	items, err := ioutil.ReadDir(folderPath)
	if err != nil {
		fmt.Printf("[!] Error reading folders under %s: %s\n", folderPath, err)
		return nil
	}

	var codeFiles []string
	for _, item := range items {
		if !item.IsDir() {
			// https://gist.github.com/aln787/ea40d18cc33c7a983549
			r, err := regexp.MatchString(ext+"$", item.Name())
			if err == nil && r {
				codeFiles = append(codeFiles, item.Name())
			}
		}
	}
	return codeFiles
}

// PrintCodeFile shows the module path in a nicer format
func PrintCodeFile(m string) string {
	return strings.TrimSuffix(strings.TrimPrefix(m, "data/"), ".xml")
}

//
// Config file functions
//

// ParseConfigFile reads a provided config file and sets up the Config struct
func ParseConfigFile(path string) (Config, error) {
	keyerBytes, err := ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var c Config
	err = yaml.Unmarshal(keyerBytes, &c)
	if err != nil {
		return Config{}, err
	}
	return c, nil
}

// ConfigLintCheck validates the config file
func ConfigLintCheck(config Config) (bool, []string) {
	// check if language exists
	if !StrInSlice(config.Language, GetLanguages()) {
		return false, []string{"Language not supported"}
	}

	// make sure there's at least one keyer
	if len(config.Keyers) == 0 {
		return false, []string{"No Keyers supplied"}
	}

	var errorsDetected []string
	// check if payload file exists
	if _, err := os.Stat(config.PayloadFile); os.IsNotExist(err) {
		errorsDetected = append(errorsDetected, config.PayloadFile+" file could not be found")
	}

	// run checks on each keyer
	for _, keyer := range config.Keyers {
		// Parsing the keyer will tell us if it actually exists
		keyerObj, err := ParseKeyer(config.Language, keyer.Name)
		if err != nil {
			e := fmt.Sprintf("Keyer '%s' does not exist", keyer.Name)
			errorsDetected = append(errorsDetected, e)
			continue
		}

		// check if keyer type is "combo" or "chain"
		if keyerObj.Type != "chain" && keyerObj.Type != "combo" {
			e := fmt.Sprintf("Keyer '%s' type is not valid: %s", keyer.Name, keyerObj.Type)
			errorsDetected = append(errorsDetected, e)
		}

		// Check length of inputs
		if len(keyer.Inputs) != keyerObj.InputNum {
			e := keyer.Name + " inputs do not match expected inputs"
			errorsDetected = append(errorsDetected, e)
		}

	}
	if len(errorsDetected) > 0 {
		return false, errorsDetected
	}
	return true, nil
}

//
// Template Stuff
//

// InputTemplate holds the Inputs so it can be sent to UpdateTemplate()
type InputTemplate struct {
	Input []string
}

// FinalCodeTemplate holds the placeholders within the BaseCode of a language
// Updating these values results in the final code
type FinalCodeTemplate struct {
	Functions       string
	Callers         string
	EncryptedBase64 string
	PayloadHash     string
	AESIVBase64     string
	MinusBytes      string
	Retries         string
	Sleep           string
	// Used for C# payloads
	AssemblyType   string
	AssemblyMethod string
}

// UpdateTemplate replaces placeholders within code files with structs
func UpdateTemplate(code string, data interface{}) (string, error) {
	tpl := template.Must(template.New("code").Parse(code))
	//tpl, err := template.Parse(code)
	buf := &bytes.Buffer{}
	err := tpl.ExecuteTemplate(buf, "code", data)
	return buf.String(), err
}
