// Copyright 2015 Factom Foundation
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/FactomProject/factom"
	ed "github.com/agl/ed25519"
)

const usage = "Usage: apiwatch conf.json"

type APICall struct {
	APIMethod string
	ChainID   string
	SecKey    string
	ECAddr    string
}

// Create a factom.Entry and commit/reveal
func (a *APICall) Factomize() error {
	type entryBody struct {
		APIMethod  string
		ReturnData string
		Timestamp  int64
	}
	b := new(entryBody)

	b.APIMethod = a.APIMethod

	// get the ReturnData from the api call
	resp, err := http.Get(a.APIMethod)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf(string(data))
	}
	b.ReturnData = string(data)

	// get the current time
	b.Timestamp = time.Now().Unix()

	// create the factom entry
	e := factom.NewEntry()

	e.ChainID = a.ChainID
	if e.Content, err = json.Marshal(b); err != nil {
		return err
	}

	// Write the signature of the Entry Content to the first ExtID
	e.ExtIDs = append(e.ExtIDs, func() []byte {
		sec := new([64]byte)
		if s, err := hex.DecodeString(a.SecKey); err != nil {
			log.Fatal(err)
		} else {
			copy(sec[:], s)
		}
		return ed.Sign(sec, e.Content)[:]
	}())

	// Commit+Reveal the Entry to the Factom Network
	if err := factom.CommitEntry(e, a.ECAddr); err != nil {
		return err
	}
	time.Sleep(10 * time.Second)
	if err := factom.RevealEntry(e); err != nil {
		return err
	}

	return nil
}

// NewConfigReader creates a function that returns the next api call from the
// config file.
func NewConfigReader(r io.Reader) func() (*APICall, error) {
	dec := json.NewDecoder(r)
	return func() (*APICall, error) {
		a := new(APICall)
		if err := dec.Decode(a); err != nil {
			return a, err
		}
		return a, nil
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal(usage)
	}

	conf, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer conf.Close()

	// error channel
	ec := make(chan error)

	// cr is type func() (*APICall, error)
	cr := NewConfigReader(conf)

	go func() {
		wg := new(sync.WaitGroup)
		for {
			a, err := cr()
			if err != nil {
				if err != io.EOF {
					ec <- err
				}
				break
			}

			// write 'a' into factom
			wg.Add(1)
			go func(a *APICall) {
				defer wg.Done()
				if err := a.Factomize(); err != nil {
					ec <- err
				}
			}(a)
		}
		wg.Wait()
		close(ec)
	}()

	// read any errors from the error chan
	for err := range ec {
		log.Println(err)
	}
}
