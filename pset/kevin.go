// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pset

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/yenkuanlee/go-elements/elementsutil"
	"github.com/yenkuanlee/go-elements/network"
	"github.com/yenkuanlee/go-elements/payment"
	"github.com/yenkuanlee/go-elements/transaction"
)

func Kevin() {
	// KEVIN NEED
	privKeyHex1 := "b02d70a2ee1717a445dc7129cfe75cef8e5ca17d7f5472bdc7e7271bf9f8a233"
	privateKeyBytes1, _ := hex.DecodeString(privKeyHex1)
	privkey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes1)
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Testnet, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	log.Printf("KEVIN1")
	// Retrieve sender utxos.
	utxos, err := Unspents(address)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("KEVIN2")

	// The transaction will have 1 input and 3 outputs.
	txInputHash := elementsutil.ReverseBytes(H2b(utxos[0]["txid"].(string)))
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	receiverValue, _ := elementsutil.SatoshiToElementsValue(6000000)
	receiverScript := H2b("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(Lbtc, receiverValue, receiverScript)

	changeScript := p2wpkh.WitnessScript
	changeValue, _ := elementsutil.SatoshiToElementsValue(3000000)
	changeOutput := transaction.NewTxOutput(Lbtc, changeValue, changeScript)

	// Create a new pset with all the outputs that need to be blinded first
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{receiverOutput, changeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		log.Fatal(err)
	}

	// Add sighash type and witness utxo to the partial input.
	updater, err := NewUpdater(p)
	if err != nil {
		log.Fatal(err)
	}

	witValue, _ := elementsutil.SatoshiToElementsValue(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(Lbtc, witValue, p2wpkh.WitnessScript)
	if err := updater.AddInWitnessUtxo(witnessUtxo, 0); err != nil {
		log.Fatal(err)
	}

	//blind outputs
	inBlindingPrvKeys := [][]byte{{}}
	outBlindingPrvKeys := make([][]byte, 2)
	for i := range outBlindingPrvKeys {
		pk, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			log.Fatal(err)
		}
		outBlindingPrvKeys[i] = pk.Serialize()
	}

	if err := BlindTransaction(
		p,
		inBlindingPrvKeys,
		outBlindingPrvKeys,
		nil,
	); err != nil {
		log.Fatal(err)
	}

	// Add the unblinded outputs now, that's only the fee output in this case
	AddFeesToTransaction(p, 1000000)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	if err := SignTransaction(p, prvKeys, scripts, true, nil); err != nil {
		log.Fatal(err)
	}

	if _, err := BroadcastTransaction(p); err != nil {
		log.Fatal(err)
	}
}

func Unspents(address string) ([]map[string]interface{}, error) {
	getUtxos := func(address string) ([]interface{}, error) {
		url := fmt.Sprintf("https://blockstream.info/liquidtestnet/api/address/%s/utxo", address)
		log.Println(url)
		method := "GET"

		client := &http.Client{}
		req, err := http.NewRequest(method, url, nil)

		if err != nil {
			return nil, err
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		data, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		var respBody interface{}
		if err := json.Unmarshal(data, &respBody); err != nil {
			return nil, err
		}
		return respBody.([]interface{}), nil
	}

	utxos := []map[string]interface{}{}
	for len(utxos) <= 0 {
		time.Sleep(1 * time.Second)
		u, err := getUtxos(address)
		if err != nil {
			return nil, err
		}
		for _, unspent := range u {
			utxo := unspent.(map[string]interface{})
			utxos = append(utxos, utxo)
		}
	}

	return utxos, nil
}

func H2b(str string) []byte {
	buf, _ := hex.DecodeString(str)
	return buf
}

var Lbtc = append(
	[]byte{0x01},
	elementsutil.ReverseBytes(H2b(network.Testnet.AssetID))...,
)

func BlindTransaction(
	p *Pset,
	inBlindKeys [][]byte,
	outBlindKeys [][]byte,
	issuanceBlindKeys []IssuanceBlindingPrivateKeys,
) error {
	outputsPrivKeyByIndex := make(map[int][]byte, 0)
	for index, output := range p.UnsignedTx.Outputs {
		if len(output.Script) > 0 {
			outputsPrivKeyByIndex[index] = outBlindKeys[index]
		}
	}

	return BlindTransactionByIndex(p, inBlindKeys, outputsPrivKeyByIndex, issuanceBlindKeys)
}

func BlindTransactionByIndex(
	p *Pset,
	inBlindKeys [][]byte,
	outBlindKeysMap map[int][]byte,
	issuanceBlindKeys []IssuanceBlindingPrivateKeys,
) error {
	outBlindPubKeysMap := make(map[int][]byte)
	for index, k := range outBlindKeysMap {
		_, pubkey := btcec.PrivKeyFromBytes(btcec.S256(), k)
		outBlindPubKeysMap[index] = pubkey.SerializeCompressed()
	}

	psetBase64, err := p.ToBase64()
	if err != nil {
		return err
	}

	for {
		blindDataLike := make([]BlindingDataLike, len(inBlindKeys), len(inBlindKeys))
		for i, inBlinKey := range inBlindKeys {
			blindDataLike[i] = PrivateBlindingKey(inBlinKey)
		}

		ptx, _ := NewPsetFromBase64(psetBase64)
		blinder, err := NewBlinder(
			ptx,
			blindDataLike,
			outBlindPubKeysMap,
			issuanceBlindKeys,
			nil,
		)
		if err != nil {
			return err
		}

		for {
			if err := blinder.Blind(); err != nil {
				if err != ErrGenerateSurjectionProof {
					return err
				}
				continue
			}
			break
		}

		verify, err := VerifyBlinding(ptx, blindDataLike, outBlindKeysMap, issuanceBlindKeys)
		if err != nil {
			return err
		}

		if verify {
			*p = *ptx
			break
		}
	}

	return nil
}

func AddFeesToTransaction(p *Pset, feeAmount uint64) {
	updater, _ := NewUpdater(p)
	feeScript := []byte{}
	feeValue, _ := elementsutil.SatoshiToElementsValue(feeAmount)
	feeOutput := transaction.NewTxOutput(Lbtc, feeValue, feeScript)
	updater.AddOutput(feeOutput)
}

func SignTransaction(
	p *Pset,
	privKeys []*btcec.PrivateKey,
	scripts [][]byte,
	forWitness bool,
	opts *SignOpts,
) error {
	updater, err := NewUpdater(p)
	if err != nil {
		return err
	}

	for i, in := range p.Inputs {
		if err := updater.AddInSighashType(txscript.SigHashAll, i); err != nil {
			return err
		}

		var prevout *transaction.TxOutput
		if in.WitnessUtxo != nil {
			prevout = in.WitnessUtxo
		} else {
			prevout = in.NonWitnessUtxo.Outputs[p.UnsignedTx.Inputs[i].Index]
		}
		prvkey := privKeys[i]
		pubkey := prvkey.PubKey()
		script := scripts[i]

		var sigHash [32]byte
		if forWitness {
			sigHash = p.UnsignedTx.HashForWitnessV0(
				i,
				script,
				prevout.Value,
				txscript.SigHashAll,
			)
		} else {
			sigHash, err = p.UnsignedTx.HashForSignature(i, script, txscript.SigHashAll)
			if err != nil {
				return err
			}
		}

		sig, err := prvkey.Sign(sigHash[:])
		if err != nil {
			return err
		}
		sigWithHashType := append(sig.Serialize(), byte(txscript.SigHashAll))

		var witPubkeyScript []byte
		var witScript []byte
		if opts != nil {
			witPubkeyScript = opts.pubkeyScript
			witScript = opts.script
		}

		if _, err := updater.Sign(
			i,
			sigWithHashType,
			pubkey.SerializeCompressed(),
			witPubkeyScript,
			witScript,
		); err != nil {
			return err
		}
	}

	valid, err := p.ValidateAllSignatures()
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid signatures")
	}

	return nil
}

type SignOpts struct {
	pubkeyScript []byte
	script       []byte
}

func BroadcastTransaction(p *Pset) (string, error) {
	// Finalize the partial transaction.
	if err := FinalizeAll(p); err != nil {
		return "", err
	}
	// Extract the final signed transaction from the Pset wrapper.
	finalTx, err := Extract(p)
	if err != nil {
		return "", err
	}
	// Serialize the transaction and try to broadcast.
	txHex, err := finalTx.ToHex()
	if err != nil {
		return "", err
	}
	log.Printf(txHex)

	return txHex, nil
}
