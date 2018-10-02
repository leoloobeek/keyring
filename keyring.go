package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/leoloobeek/keyring/lib"
)

func main() {
	flag.Usage = usage
	conf := flag.String("config", "", "Config file to read.")
	request := flag.String("request", "", "Request and retrieve an HTTP or DNS key.")
	helpKeyer := flag.String("help-keyer", "", "Show detailed help information for a specific keyer. expects <lang>/<keyer>")
	listLangs := flag.Bool("list-langs", false, "List all languages.")
	listKeyers := flag.String("list-keyers", "", "List all keyers for a specified language.")
	lint := flag.Bool("lint", false, "Check config file for errors and print functionality without running GoGreen.")
	flag.Parse()

	banner()

	// If we're just going to request a DNS or HTTP key, lets do that and get out
	if *request != "" {
		retrieveRemoteKeys(*request)
		return
	}

	// Print help details for a keyer
	if *helpKeyer != "" {
		PrintKeyerHelp(*helpKeyer)
		return
	}

	// List all languages
	if *listLangs {
		listAllSupportedLangs()
		return
	}

	// List all keyers
	if *listKeyers != "" {
		listAllSupportedKeyers(*listKeyers)
		return
	}

	if *conf == "" {
		fmt.Println("[!] No config file provided")
		return
	}
	// Read in the config file
	config, err := lib.ParseConfigFile(*conf)
	if err != nil {
		fmt.Printf("[!] Error received parsing config file: %s\n", err)
		return
	}

	// Make sure config settings are valid
	result, errorsFound := lib.ConfigLintCheck(config)
	if !result {
		fmt.Println("[!] Config file contains invalid entries!")
		fmt.Printf("Errors detected from %s:\n", *conf)
		for _, e := range errorsFound {
			fmt.Printf("\t%s\n", e)
		}
		return
	}

	if *lint {
		fmt.Printf("[+] Config file %s valid", *conf)
		return
	}

	finalKey, keyHash, payloadHash, outputFile, minusBytes := Run(config)

	fmt.Println()
	fmt.Println("    Raw Key:")
	fmt.Printf("         %s\n", finalKey)
	fmt.Println("    Final Key Hash:")
	fmt.Printf("         %s\n", keyHash)
	fmt.Println("    Payload Hash (Minus Bytes):")
	fmt.Printf("         %s (%d)\n", payloadHash, minusBytes)
	fmt.Printf("     Payload written to %s\n", outputFile)
	fmt.Println()
}

// Run does all the fun stuff
func Run(config lib.Config) (string, string, string, string, int) {

	// Read in payload and get hash
	payloadBytes, payloadHash, minusBytes := GetPayloadDetails(config.PayloadFile, "sha512")

	// Variables to hold things
	var callers bytes.Buffer
	var keyCombos bytes.Buffer
	var keyChains bytes.Buffer
	// string holds the keyer name the function came from to avoid holding more
	// than one function per keyer
	functionMap := map[string]string{}

	// Loop through each keyer and get necessary info
	for _, keyer := range config.Keyers {
		keyerObj, err := lib.ParseKeyer(config.Language, keyer.Name)
		if err != nil {
			fmt.Printf("[!] Unknown keyer: %s\n", keyer.Name)
		}

		funcExists := false
		// check if this function has already been added
		for f := range functionMap {
			if f == keyer.Name {
				funcExists = true
			}
		}
		// add function if it hasn't already been added
		if !funcExists {
			function, err := lib.UpdateTemplate(keyerObj.Function, keyer)
			if err != nil {
				fmt.Printf("[!] Error updating %s's function template with inputs\n", keyer.Name)
				fmt.Println(err)
			}
			functionMap[keyer.Name] = strings.Trim(function, "\n  ")
		}

		// update the callers
		caller, err := lib.UpdateTemplate(keyerObj.Caller, keyer)
		if err != nil {
			fmt.Printf("[!] Error updating %s's keyer template with inputs\n", keyer.Name)
			fmt.Println(err)
		}
		callers.WriteString(strings.Trim(caller, "\n  "))

		// finally, update the key depending on type
		if keyerObj.Type == "chain" {
			keyChains.WriteString(keyer.Output)
			callers.WriteString("\n")
		} else if keyerObj.Type == "combo" {
			keyCombos.WriteString(keyer.Output)
			callers.WriteString("\n")
		} else {
			fmt.Printf("[!] The keyer type %s is unknown\n", keyerObj.Type)
		}
	}
	// convert map to a string for use
	functions := functionMapToString(functionMap)

	finalKey := strings.ToLower(keyCombos.String() + keyChains.String())
	keyHash, err := lib.GenerateHash([]byte(finalKey), "sha512")
	if err != nil {
		fmt.Println("[!] Error generating hash for final key")
	}

	// Returns base64 encoded ciphertext and base64 encoded IV
	encryptedB64, ivB64, err := lib.AESEncrypt([]byte(keyHash[:32]), payloadBytes)
	if err != nil {
		fmt.Printf("[!] Error received encrypting: %s", err)
		return "", "", "", "", 0
	}

	base, _ := lib.ParseLanguage(config.Language)

	// empty sleep var if retries = 0
	if config.Retries == "0" {
		config.Sleep = ""
	}

	minusByteString := strconv.Itoa(minusBytes)
	placeholders := lib.FinalCodeTemplate{
		Functions:       functions,
		Callers:         callers.String(),
		EncryptedBase64: encryptedB64,
		AESIVBase64:     ivB64,
		PayloadHash:     payloadHash,
		MinusBytes:      minusByteString,
		Retries:         config.Retries,
		Sleep:           config.Sleep,
	}

	additionalLangUpdates(base.Name, &placeholders, &config)

	finalCode, err := lib.UpdateTemplate(base.BaseCode, placeholders)
	if err != nil {
		fmt.Printf("[!] Error updating final template: %s\n", err)
		return "", "", "", "", 0
	}

	if config.OutputFile == "" {
		config.OutputFile = "output." + base.Extension
	}

	lib.WriteFile(config.OutputFile, []byte(finalCode))

	return finalKey, keyHash, payloadHash, config.OutputFile, minusBytes
}

// additionalLangUpdates adds in any other FinalCodeTemplate attributes which are
// specific to certain languages. Wish this wasn't needed, but some languages just
// need a little more data.
func additionalLangUpdates(language string, fct *lib.FinalCodeTemplate, config *lib.Config) {
	if language == "csharp" {
		fct.AssemblyType = config.AssemblyType
		fct.AssemblyMethod = config.AssemblyMethod
	}
}

// PrintKeyerHelp takes <lang>/<keyer> and prints keyer help if valid
func PrintKeyerHelp(input string) {
	s := strings.Split(input, "/")
	if len(s) != 2 {
		fmt.Println("[!] <lang>/<keyer> expected. Use '-list' to find available keyers")
		return
	}
	keyer, err := lib.ParseKeyer(s[0], s[1])
	if err != nil {
		fmt.Printf("[!] Error trying to parse %s: %s", input, err)
		return
	}
	fmt.Printf("Keyer: %s\n", keyer.Name)
	fmt.Printf("\t%s\n", keyer.Title)
	fmt.Printf("Type: %s\n", keyer.Type)
	fmt.Println(strings.Trim(keyer.InputHelp, "\n  "))
}

// GetPayloadDetails reads in the payload file and returns the contents,
// payload hash, and minus bytes. Minus bytes are randomly chosen between
// len(payload)/2 -> len(payload)-1
func GetPayloadDetails(payloadFile, hashType string) ([]byte, string, int) {
	fileContents, err := lib.ReadFile(payloadFile)
	if err != nil {
		fmt.Printf("[!] %s: %s\n", payloadFile, err)
		return nil, "", 0
	}

	// Figure out Minus Bytes
	num := len(fileContents) / 2
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	minusBytes := r.Intn(num)
	if minusBytes == 0 {
		minusBytes = 1
	}
	index := len(fileContents) - minusBytes

	// Generate the hash of the payload for a checksum
	payloadHash, err := lib.GenerateHash(fileContents[:index], hashType)
	if err != nil {
		fmt.Printf("[!] Error generating hash for payload: %s\n", err)
		return nil, "", 0
	}

	return fileContents, payloadHash, minusBytes
}

func listAllSupportedLangs() {
	fmt.Println("Supported Languages:")
	supportedLangs := lib.GetLanguages()

	for _, lang := range supportedLangs {
		l, err := lib.ParseLanguage(lang)
		if err != nil {
			fmt.Printf("[!] Error parsing %s: %s\n", lang, err)
			continue
		}
		fmt.Printf("- %s\n", l.Name)
	}
}

// list all keyers for provided language
func listAllSupportedKeyers(lang string) {
	l, err := lib.ParseLanguage(lang)
	if err != nil {
		fmt.Printf("[!] Error parsing %s: %s\n", lang, err)
		return
	}
	fmt.Printf("Supported Keyers (%s):\n", l.Name)
	for _, codeFile := range lib.GetCodeFiles(lang, "keyers") {
		k, err := lib.ParseKeyerFile(lang, codeFile)
		if err != nil {
			fmt.Printf("[!] Error parsing %s: %s\n", codeFile, err)
			continue
		}
		fmt.Printf("    - %s (%s)\n", k.Name, k.Title)
		fmt.Printf("\t%s\n", k.Description)
	}
}

// build functions string through values of functionMap
func functionMapToString(fMap map[string]string) string {
	var functions bytes.Buffer
	for _, value := range fMap {
		functions.WriteString(value)
		functions.WriteString("\n")
	}
	return functions.String()
}

// handles -request flag to retrieve a DNS or HTTP key
func retrieveRemoteKeys(request string) {
	// if request is a URL, obtain an HTTP key
	if strings.HasPrefix(request, "http://") || strings.HasPrefix(request, "https://") {
		httpKey, err := lib.GenerateHttpKey(request)
		if err != nil {
			fmt.Printf("[!] Error receiving HTTP key for %s: %s\n", request, err)
			return
		}
		fmt.Printf("HTTP Key retrieved for %s\n", request)
		fmt.Println(httpKey)
	} else {
		// If not http:// or https:// lets try DNS
		// Do DNS A first
		fmt.Println("DNS A Request:")
		dnsA, dnsAHash, err := lib.GenerateDNSAKey(request)
		if err != nil {
			fmt.Printf("\tError received request A record: %s\n", err)
		} else {
			fmt.Printf("\tDNS Response:     %s\n", dnsA)
			fmt.Printf("\tHash of Response: %s\n", dnsAHash)
		}

		// Do DNS TXT
		fmt.Println("DNS TXT Request:")
		dnsTXT, dnsTXTHash, err := lib.GenerateDNSTXTKey(request)
		if err != nil {
			fmt.Printf("\tError received request TXT record: %s\n", err)
		} else {
			fmt.Printf("\tDNS Response:     %s\n", dnsTXT)
			fmt.Printf("\tHash of Response: %s\n", dnsTXTHash)
		}
	}
}

// not worth leveraging a third-party package but the included
// flag package's usage printout isn't nice enough for me
func usage() {
	name := "keyring"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	fmt.Printf("\nUsage: %s [options] \n\n", name)

	// core functionality
	fmt.Println("    Generate Keyed Payload:")
	fmt.Println("\t--config <config.yml>")
	fmt.Println("\t    Config file to read. Required.")
	fmt.Println("\t--lint")
	fmt.Println("\t    Check config file for errors and print functionality without running keyring.")
	fmt.Println()

	// list items
	fmt.Println("    Find language and keyer details:")
	fmt.Println("\t--list-langs")
	fmt.Println("\t    List all languages.")
	fmt.Println("\t--list-keyers <lang>")
	fmt.Println("\t    List all keyers for a specified language.")
	fmt.Println("\t--help-keyer <lang>/<keyer>")
	fmt.Println("\t    Show detailed help information for a specific keyer.")
	fmt.Println()

	// retrieve things
	fmt.Println("    Grab remote keys:")
	fmt.Println("\t--request <string>")
	fmt.Println("\t    Request and retrieve an HTTP or DNS key. Expects URL or hostname.")
	fmt.Println()
}

// http://ascii.co.uk/art/key
func banner() {
	b := `
   .--. KeyRing 1.0
  /.-. '------------.
  \'-' .--"--""-"-"-'
   '--'`

	fmt.Println()
	fmt.Println(b)
	fmt.Println()
}
