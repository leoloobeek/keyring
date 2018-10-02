package lib

import (
	"errors"
	"io/ioutil"
	"os"
)

// ReadFile reads a file given the path and returns a byte slice
func ReadFile(path string) ([]byte, error) {
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New("(ReadFile) Error reading file")
	}
	return fileBytes, nil
}

// WriteFile writes a file given the path and a byte slice
func WriteFile(filename string, contents []byte) {
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	_, err = f.Write(contents)
	if err != nil {
		panic(err)
	}
}

// StrInSlice checks if a string exists in a slice. No convenient "in" with Go
// https://stackoverflow.com/questions/15323767/does-go-have-if-x-in-construct-similar-to-python
func StrInSlice(s string, l []string) bool {
	for _, val := range l {
		if val == s {
			return true
		}
	}
	return false
}
