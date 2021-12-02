// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pset

import (
	"encoding/hex"
	"log"

	"github.com/btcsuite/btcd/btcec"
	"github.com/yenkuanlee/go-elements/elementsutil"
	"github.com/yenkuanlee/go-elements/network"
	"github.com/yenkuanlee/go-elements/payment"
	"github.com/yenkuanlee/go-elements/transaction"
)

func Kevin() {
	/**
	* This test attempts to broadcast a confidential transaction composed by 1
	* P2WPKH unbinded input and 2 blinded outputs. The outputs will be a
	* confidential p2sh for the receiver and a confidential p2wpkh for the
	* change. A 3rd unblinded output is for the fees with empty script.
	**/
	// KEVIN NEED
	privKeyHex1 := "b02d70a2ee1717a445dc7129cfe75cef8e5ca17d7f5472bdc7e7271bf9f8a233"
	privateKeyBytes1, _ := hex.DecodeString(privKeyHex1)
	privkey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes1)
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Testnet, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	log.Printf("KEVIN1")
	// Retrieve sender utxos.
	utxos, err := unspents(address)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("KEVIN2")

	// The transaction will have 1 input and 3 outputs.
	txInputHash := elementsutil.ReverseBytes(h2b(utxos[0]["txid"].(string)))
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	receiverValue, _ := elementsutil.SatoshiToElementsValue(6000000)
	receiverScript := h2b("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue, receiverScript)

	changeScript := p2wpkh.WitnessScript
	changeValue, _ := elementsutil.SatoshiToElementsValue(3000000)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue, changeScript)

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
	witnessUtxo := transaction.NewTxOutput(lbtc, witValue, p2wpkh.WitnessScript)
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

	if err := blindTransaction(
		p,
		inBlindingPrvKeys,
		outBlindingPrvKeys,
		nil,
	); err != nil {
		log.Fatal(err)
	}

	// Add the unblinded outputs now, that's only the fee output in this case
	addFeesToTransaction(p, 1000000)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	if err := signTransaction(p, prvKeys, scripts, true, nil); err != nil {
		log.Fatal(err)
	}

	if _, err := broadcastTransaction(p); err != nil {
		log.Fatal(err)
	}
}
