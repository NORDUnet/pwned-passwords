package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
)

type pwdb struct {
	f           *os.File
	n           int
	rs          int
	hash_length int
}

func Pwdb_open(fn string) (error, *pwdb) {
	f, err := os.Open(fn)
	if err != nil {
		return err, nil
	}

	stat, err := f.Stat()
	if err != nil {
		return err, nil
	}

	const rs = 63 // V2 has fixed with of 63 bytes
	if stat.Size()%rs != 0 {
		return fmt.Errorf("Unexpected password file format (must be a text file with 63 char width starting with sha1)"), nil
	}
	const hash_length = 40 // sha1 is 40 chars

	return nil, &pwdb{f, int(stat.Size() / rs), rs, hash_length}
}

func (db *pwdb) record(i int) string {
	b := make([]byte, db.hash_length)
	db.f.ReadAt(b, int64(i*db.rs))
	return string(b)
}

func (db *pwdb) Search(cleartext string) bool {
	hasher := sha1.New()
	io.WriteString(hasher, cleartext)
	return db.SearchHash(hex.EncodeToString(hasher.Sum(nil)))
}

func (db *pwdb) SearchHash(hash string) bool {
	// check hash length return false?
	needle := strings.ToUpper(hash)

	i := sort.Search(db.n, func(i int) bool {
		return db.record(i) >= needle
	})
	return i < db.n && db.record(i) == needle
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <path-to-pwned-passwords-1.0.txt> <password-to-test>...\n", os.Args[0])
	}

	err, db := Pwdb_open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	for i := 2; i < len(os.Args); i++ {
		if db.Search(os.Args[i]) {
			fmt.Printf("%s: FOUND\n", os.Args[i])
		} else {
			fmt.Printf("%s: not found\n", os.Args[i])
		}
	}
}
