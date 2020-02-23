package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

var (
	ctextSamplesFile = "ctexts"
	targetCtext      = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
)

func loadSampleCipherTexts(file string) ([][]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ctexts [][]byte

	scn := bufio.NewScanner(f)
	for scn.Scan() {
		b, err := hex.DecodeString(scn.Text())
		if err != nil {
			return nil, err
		}

		ctexts = append(ctexts, b)
	}

	return ctexts, scn.Err()
}

func xorBytes(d, a, b []byte) {
	for i := range d {
		d[i] = a[i] ^ b[i]
	}
}

func isEnglishASCIIChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z':
	case 'A' <= c && c <= 'Z':
	case c == ' ' || c == ',' || c == '.' || c == '\'' || c == ':' || c == ')' || c == '(' || c == '-':
	default:
		return false
	}

	return true
}

func isEnglishASCII(b []byte) bool {
	for _, c := range b {
		if !isEnglishASCIIChar(c) {
			return false
		}
	}

	return true
}

// guessCrib assumes that `i`th ptext at position `pos` has the crib, and
// calculate ptexts for other indices.
func guessCrib(crib []byte, i, pos int, ctexts [][]byte) {
	buf := make([]byte, len(crib))

	ptexts := make([]string, len(ctexts))

	// print if >70% of guessed characters do not contain unacceptable characters

	var ninvalid int
	for j, ctext := range ctexts {
		if i == j {
			ptexts[j] = string(crib)
			continue
		}

		a := ctexts[i][pos:]
		b := ctext[pos:]

		xorBytes(buf, a, b)
		xorBytes(buf, buf, crib)

		ptexts[j] = string(buf)
		if !isEnglishASCII(buf) {
			ninvalid++
		}
	}

	score := 1 - float64(ninvalid)/10
	// fmt.Println("score:", score)

	if score > 0.7 {
		fmt.Printf("%02d pos=%02d %#v \n", i, pos, ptexts)
	}
}

func guessCribInAll(crib []byte, ctexts [][]byte) {
	length := len(ctexts[0])
	fmt.Printf("####################################\ncrib = %#v\n", string(crib))

	for i := 0; i < len(ctexts)-1; i++ {
		for pos := 0; pos <= length-len(crib); pos++ {
			guessCrib(crib, i, pos, ctexts)
		}
	}
}

func solveKey(key, ctext []byte, pos int, ptext []byte) {
	// c = p ^ k
	// k = c ^ p
	xorBytes(key[pos:pos+len(ptext)], ctext[pos:], ptext)
}

func run() error {
	ctexts, err := loadSampleCipherTexts(ctextSamplesFile)
	if err != nil {
		return err
	}

	// truncate all ctexts to same length as the shortest (the first)
	target := ctexts[0]
	for i, ctext := range ctexts {
		ctexts[i] = ctext[:len(target)]
	}

	// log.Println("ctexts", ctexts)
	// guess if the first three characters are "The"
	// guessCrib([]byte("The"), 0, 0, ctexts)
	// guessCribInAll([]byte(" the "), ctexts)
	// guessCribInAll([]byte(" be "), ctexts)
	// guessCribInAll([]byte(" to "), ctexts)
	// guessCribInAll([]byte(" of "), ctexts)
	// guessCribInAll([]byte(" and "), ctexts)
	// guessCribInAll([]byte(" in "), ctexts)
	// guessCribInAll([]byte(" it "), ctexts)
	// guessCribInAll([]byte(" for "), ctexts)
	// guessCribInAll([]byte(" not "), ctexts)
	// guessCribInAll([]byte(" with "), ctexts)
	// guessCribInAll([]byte(" that "), ctexts)
	// guessCribInAll([]byte("crypto"), ctexts)
	// guessCribInAll([]byte("cyptography"), ctexts) // LOL typo?
	// guessCribInAll([]byte("number"), ctexts)
	// guessCribInAll([]byte("secret"), ctexts)
	// guessCribInAll([]byte("probably"), ctexts)
	// guessCribInAll([]byte("computer"), ctexts)
	// guessCribInAll([]byte("factor"), ctexts)
	// guessCribInAll([]byte("use"), ctexts)
	// guessCribInAll([]byte("never "), ctexts)
	// guessCribInAll([]byte(" don't "), ctexts)
	// guessCribInAll([]byte(" algorithm "), ctexts)
	// guessCribInAll([]byte("stream"), ctexts)
	// guessCribInAll([]byte("keys"), ctexts)
	// guessCribInAll([]byte("encryption"), ctexts)
	// guessCribInAll([]byte("a stream cipher"), ctexts)
	guessCribInAll([]byte("car"), ctexts)
	guessCribInAll([]byte("once"), ctexts)

	// try " the " in different positions for all cipher texts

	key := make([]byte, len(target))

	solveKey(key, ctexts[0], 0, []byte("The "))
	solveKey(key, ctexts[0], 60, []byte(" the "))
	solveKey(key, ctexts[1], 13, []byte(" the "))
	solveKey(key, ctexts[1], 70, []byte(" the "))
	solveKey(key, ctexts[7], 51, []byte(" the "))
	solveKey(key, ctexts[8], 10, []byte(" the "))
	solveKey(key, ctexts[8], 26, []byte(" the ")) // unsure

	solveKey(key, ctexts[5], 14, []byte(" to "))
	solveKey(key, ctexts[7], 66, []byte(" to "))

	solveKey(key, ctexts[2], 70, []byte(" of ")) // redundant
	solveKey(key, ctexts[3], 69, []byte(" of "))
	solveKey(key, ctexts[5], 27, []byte(" of "))
	solveKey(key, ctexts[6], 19, []byte(" of "))

	solveKey(key, ctexts[9], 74, []byte(" for "))
	solveKey(key, ctexts[1], 27, []byte(" with "))
	solveKey(key, ctexts[6], 37, []byte(" with "))
	solveKey(key, ctexts[7], 39, []byte(" with "))

	solveKey(key, ctexts[2], 74, []byte("crypto"))
	solveKey(key, ctexts[3], 39, []byte("crypto"))
	solveKey(key, ctexts[6], 23, []byte("crypto"))

	solveKey(key, ctexts[7], 23, []byte("cyptography"))
	solveKey(key, ctexts[1], 18, []byte("number"))
	solveKey(key, ctexts[6], 59, []byte("secret"))
	solveKey(key, ctexts[1], 41, []byte("computer"))
	solveKey(key, ctexts[1], 7, []byte("factor"))
	solveKey(key, ctexts[1], 64, []byte("factor"))
	solveKey(key, ctexts[0], 57, []byte("use"))
	solveKey(key, ctexts[0], 51, []byte("never "))
	solveKey(key, ctexts[5], 3, []byte(" don't "))
	solveKey(key, ctexts[4], 44, []byte(" algorithm "))
	solveKey(key, ctexts[0], 36, []byte("stream"))
	solveKey(key, ctexts[9], 17, []byte("encryption"))

	solveKey(key, ctexts[5], 35, []byte("keys"))
	solveKey(key, ctexts[0], 34, []byte("a stream cipher"))
	solveKey(key, ctexts[3], 79, []byte("car"))
	solveKey(key, ctexts[0], 79, []byte("once"))

	fmt.Printf("key: %x\n", key)

	// solve all ctext
	ptext := make([]byte, len(target))
	for i, ctext := range ctexts {
		xorBytes(ptext, ctext, key)

		// for i, c := range ptext {
		// 	if !isEnglishASCIIChar(c) {
		// 		ptext[i] = '#'
		// 		// ptext[i] = c
		// 	}
		// }

		fmt.Printf("%02d %#v\n", i, string(ptext))
	}

	return nil
}

func main() {
	err := run()
	if err != nil {
		log.Fatalln(err)
	}
}
