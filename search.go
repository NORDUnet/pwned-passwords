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
	f  *os.File
	n  int
	rs int
}

func pwdb_open(fn string) (error, *pwdb) {
	f, err := os.Open(os.Args[1])
	if err != nil {
		return err, nil
	}

	stat, err := f.Stat()
	if err != nil {
		return err, nil
	}

	const rs = 2*20 + 1 + 1 // 20 bytes * 2 (hex encoding) + cr + lf
	if stat.Size()%rs != 0 {
		return fmt.Errorf("Unexpected password file format (must be a text file file 1 sha1 hash per line, cr, lf)"), nil
	}

	return nil, &pwdb{f, int(stat.Size() / rs), rs}
}

func (db *pwdb) record(i int) string {
	b := make([]byte, db.rs)
	db.f.ReadAt(b, int64(i*db.rs))
	return string(b)
}

func (db *pwdb) search(cleartext string) bool {
	hasher := sha1.New()
	io.WriteString(hasher, cleartext)
	needle := strings.ToUpper(hex.EncodeToString(hasher.Sum(nil))) + "\r\n"

	i := sort.Search(db.n, func(i int) bool {
		return db.record(i) >= needle
	})
	return i < db.n && db.record(i) == needle
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <path-to-pwned-passwords-1.0.txt> <password-to-test>...\n", os.Args[0])
	}

	err, db := pwdb_open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	for i := 2; i < len(os.Args); i++ {
		if db.search(os.Args[i]) {
			fmt.Printf("%s: FOUND\n", os.Args[i])
		} else {
			fmt.Printf("%s: not found\n", os.Args[i])
		}
	}
}
