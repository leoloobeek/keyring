package lib

import (
	"io/ioutil"
	"net"
	"net/http"
)

// GenerateHTTPKey reaches out to url, hashes the body and returns
// the sha512 hash
func GenerateHTTPKey(url string) (string, error) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "GoGreen User Agent")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	httpKey, _ := GenerateHash(result, "sha512")
	return httpKey, nil
}

// GenerateDNSAKey requests DNS A record, hashes the response and
// returns the DNS response and the sha512 hash
// Note: Only works with the first response and ignores multiple responses
func GenerateDNSAKey(hostname string) (string, string, error) {
	resp, err := net.LookupHost(hostname)
	if err != nil {
		return "", "", err
	}
	result := resp[0]

	hash, _ := GenerateHash([]byte(result), "sha512")
	return result, hash, nil
}

// GenerateDNSTXTKey requests DNS A record, hashes the response and
// returns the DNS response and the sha512 hash
// Note: Only works with the first response and ignores multiple responses
func GenerateDNSTXTKey(hostname string) (string, string, error) {
	resp, err := net.LookupTXT(hostname)
	if err != nil {
		return "", "", err
	}
	result := resp[0]

	hash, _ := GenerateHash([]byte(result), "sha512")
	return result, hash, nil
}
