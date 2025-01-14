// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pset

// The Updater requires provision of a single PSBT and is able to add data to
// both input and output sections.  It can be called repeatedly to add more
// data.  It also allows addition of signatures via the addPartialSignature
// function; this is called internally to the package in the Sign() function of
// Updater, located in signer.go

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/psbt"
	"github.com/yenkuanlee/go-elements/address"
	"github.com/yenkuanlee/go-elements/elementsutil"
	"github.com/yenkuanlee/go-elements/transaction"
)

const (
	NonConfidentialReissuanceTokenFlag = 0
	ConfidentialReissuanceTokenFlag    = 1
)

// Updater encapsulates the role 'Updater' as specified in BIP174; it accepts
// Psbt structs and has methods to add fields to the inputs and outputs.
type Updater struct {
	Data *Pset
}

// NewUpdater returns a new instance of Updater, if the passed Psbt struct is
// in a valid form, else an error.
func NewUpdater(p *Pset) (*Updater, error) {
	if err := p.SanityCheck(); err != nil {
		return nil, err
	}

	return &Updater{Data: p}, nil

}

// AddInNonWitnessUtxo adds the utxo information for an input which is
// non-witness. This requires provision of a full transaction (which is the
// source of the corresponding prevOut), and the input index. If addition of
// this key-value pair to the Psbt fails, an error is returned.
func (p *Updater) AddInNonWitnessUtxo(tx *transaction.Transaction, inIndex int) error {
	if inIndex > len(p.Data.Inputs)-1 {
		return psbt.ErrInvalidPrevOutNonWitnessTransaction
	}

	p.Data.Inputs[inIndex].NonWitnessUtxo = tx

	if err := p.Data.SanityCheck(); err != nil {
		return psbt.ErrInvalidPsbtFormat
	}

	return nil
}

// AddInWitnessUtxo adds the utxo information for an input which is witness.
// This requires provision of a full transaction *output* (which is the source
// of the corresponding prevOut); not the full transaction because BIP143 means
// the output information is sufficient, and the input index. If addition of
// this key-value pair to the Psbt fails, an error is returned.
func (p *Updater) AddInWitnessUtxo(txout *transaction.TxOutput, inIndex int) error {
	if inIndex > len(p.Data.Inputs)-1 {
		return psbt.ErrInvalidPsbtFormat
	}

	p.Data.Inputs[inIndex].WitnessUtxo = txout

	if err := p.Data.SanityCheck(); err != nil {
		return psbt.ErrInvalidPsbtFormat
	}

	return nil
}

// addPartialSignature allows the Updater role to insert fields of type partial
// signature into a Pset, consisting of both the pubkey (as keydata) and the
// ECDSA signature (as value).  Note that the Signer role is encapsulated in
// this function; signatures are only allowed to be added that follow the
// sanity-check on signing rules explained in the BIP under `Signer`; if the
// rules are not satisfied, an ErrInvalidSignatureForInput is returned.
//
// NOTE: This function does *not* validate the ECDSA signature itself.
func (p *Updater) addPartialSignature(inIndex int, sig []byte,
	pubkey []byte) error {

	partialSig := psbt.PartialSig{
		PubKey: pubkey, Signature: sig,
	}

	// First validate the passed (sig, pub).
	if !checkValid(partialSig) {
		return psbt.ErrInvalidPsbtFormat
	}

	pInput := p.Data.Inputs[inIndex]

	// First check; don't add duplicates.
	for _, x := range pInput.PartialSigs {
		if bytes.Equal(x.PubKey, partialSig.PubKey) {
			return psbt.ErrDuplicateKey
		}
	}

	// Next, we perform a series of additional sanity checks.
	if pInput.NonWitnessUtxo != nil {
		if len(p.Data.UnsignedTx.Inputs) < inIndex+1 {
			return psbt.ErrInvalidPrevOutNonWitnessTransaction
		}

		if txHash := pInput.NonWitnessUtxo.TxHash(); !bytes.Equal(txHash[:], p.Data.UnsignedTx.Inputs[inIndex].Hash) {
			return psbt.ErrInvalidSignatureForInput
		}

		// To validate that the redeem script matches, we must pull out
		// the scriptPubKey of the corresponding output and compare
		// that with the P2SH scriptPubKey that is generated by
		// redeemScript.
		if pInput.RedeemScript != nil {
			outIndex := p.Data.UnsignedTx.Inputs[inIndex].Index
			scriptPubKey := pInput.NonWitnessUtxo.Outputs[outIndex].Script
			scriptHash := btcutil.Hash160(pInput.RedeemScript)

			scriptHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_HASH160).
				AddData(scriptHash).
				AddOp(txscript.OP_EQUAL).
				Script()
			if err != nil {
				return err
			}

			if !bytes.Equal(scriptHashScript, scriptPubKey) {
				return psbt.ErrInvalidSignatureForInput
			}
		}

	} else if pInput.WitnessUtxo != nil {
		scriptPubKey := pInput.WitnessUtxo.Script

		var script []byte
		if pInput.RedeemScript != nil {
			scriptHash := btcutil.Hash160(pInput.RedeemScript)
			scriptHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_HASH160).
				AddData(scriptHash).
				AddOp(txscript.OP_EQUAL).
				Script()
			if err != nil {
				return err
			}

			if !bytes.Equal(scriptHashScript, scriptPubKey) {
				return psbt.ErrInvalidSignatureForInput
			}

			script = pInput.RedeemScript
		} else {
			script = scriptPubKey
		}

		// If a witnessScript field is present, this is a P2WSH,
		// whether nested or not (that is handled by the assignment to
		// `script` above); in that case, sanity check that `script` is
		// the p2wsh of witnessScript. Contrariwise, if no
		// witnessScript field is present, this will be signed as
		// p2wkh.
		if pInput.WitnessScript != nil {
			witnessScriptHash := sha256.Sum256(pInput.WitnessScript)
			witnessScriptHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_0).
				AddData(witnessScriptHash[:]).
				Script()
			if err != nil {
				return err
			}

			if !bytes.Equal(script, witnessScriptHashScript[:]) {
				return psbt.ErrInvalidSignatureForInput
			}
		} else {
			// Otherwise, this is a p2wkh input.
			pubkeyHash := btcutil.Hash160(pubkey)
			pubkeyHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_0).
				AddData(pubkeyHash).
				Script()
			if err != nil {
				return err
			}

			// Validate that we're able to properly reconstruct the
			// witness program.
			if !bytes.Equal(pubkeyHashScript, script) {
				return psbt.ErrInvalidSignatureForInput
			}
		}
	} else {

		// Attaching signature without utxo field is not allowed.
		return psbt.ErrInvalidPsbtFormat
	}

	p.Data.Inputs[inIndex].PartialSigs = append(
		p.Data.Inputs[inIndex].PartialSigs, &partialSig,
	)

	if err := p.Data.SanityCheck(); err != nil {
		return err
	}

	// Addition of a non-duplicate-key partial signature cannot violate
	// sanity-check rules.
	return nil
}

// AddInSighashType adds the sighash type information for an input.  The
// sighash type is passed as a 32 bit unsigned integer, along with the index
// for the input. An error is returned if addition of this key-value pair to
// the Psbt fails.
func (p *Updater) AddInSighashType(sighashType txscript.SigHashType,
	inIndex int) error {

	p.Data.Inputs[inIndex].SighashType = sighashType

	if err := p.Data.SanityCheck(); err != nil {
		return err
	}
	return nil
}

// AddInRedeemScript adds the redeem script information for an input.  The
// redeem script is passed serialized, as a byte slice, along with the index of
// the input. An error is returned if addition of this key-value pair to the
// Psbt fails.
func (p *Updater) AddInRedeemScript(redeemScript []byte,
	inIndex int) error {

	p.Data.Inputs[inIndex].RedeemScript = redeemScript

	if err := p.Data.SanityCheck(); err != nil {
		return psbt.ErrInvalidPsbtFormat
	}

	return nil
}

// AddInWitnessScript adds the witness script information for an input.  The
// witness script is passed serialized, as a byte slice, along with the index
// of the input. An error is returned if addition of this key-value pair to the
// Psbt fails.
func (p *Updater) AddInWitnessScript(witnessScript []byte,
	inIndex int) error {

	p.Data.Inputs[inIndex].WitnessScript = witnessScript

	if err := p.Data.SanityCheck(); err != nil {
		return err
	}

	return nil
}

// AddInBip32Derivation takes a master key fingerprint as defined in BIP32, a
// BIP32 path as a slice of uint32 values, and a serialized pubkey as a byte
// slice, along with the integer index of the input, and inserts this data into
// that input.
//
// NOTE: This can be called multiple times for the same input.  An error is
// returned if addition of this key-value pair to the Psbt fails.
func (p *Updater) AddInBip32Derivation(masterKeyFingerprint uint32,
	bip32Path []uint32, pubKeyData []byte, inIndex int) error {

	bip32Derivation := psbt.Bip32Derivation{
		PubKey:               pubKeyData,
		MasterKeyFingerprint: masterKeyFingerprint,
		Bip32Path:            bip32Path,
	}

	if !validatePubkey(bip32Derivation.PubKey) {
		return psbt.ErrInvalidPsbtFormat
	}

	// Don't allow duplicate keys
	for _, x := range p.Data.Inputs[inIndex].Bip32Derivation {
		if bytes.Equal(x.PubKey, bip32Derivation.PubKey) {
			return psbt.ErrDuplicateKey
		}
	}

	p.Data.Inputs[inIndex].Bip32Derivation = append(
		p.Data.Inputs[inIndex].Bip32Derivation, &bip32Derivation,
	)

	if err := p.Data.SanityCheck(); err != nil {
		return err
	}

	return nil
}

// AddOutBip32Derivation takes a master key fingerprint as defined in BIP32, a
// BIP32 path as a slice of uint32 values, and a serialized pubkey as a byte
// slice, along with the integer index of the output, and inserts this data
// into that output.
//
// NOTE: That this can be called multiple times for the same output.  An error
// is returned if addition of this key-value pair to the Psbt fails.
func (p *Updater) AddOutBip32Derivation(masterKeyFingerprint uint32,
	bip32Path []uint32, pubKeyData []byte, outIndex int) error {

	bip32Derivation := psbt.Bip32Derivation{
		PubKey:               pubKeyData,
		MasterKeyFingerprint: masterKeyFingerprint,
		Bip32Path:            bip32Path,
	}

	if !validatePubkey(bip32Derivation.PubKey) {
		return psbt.ErrInvalidPsbtFormat
	}

	// Don't allow duplicate keys
	for _, x := range p.Data.Outputs[outIndex].Bip32Derivation {
		if bytes.Equal(x.PubKey, bip32Derivation.PubKey) {
			return psbt.ErrDuplicateKey
		}
	}

	p.Data.Outputs[outIndex].Bip32Derivation = append(
		p.Data.Outputs[outIndex].Bip32Derivation, &bip32Derivation,
	)

	if err := p.Data.SanityCheck(); err != nil {
		return err
	}

	return nil
}

// AddOutRedeemScript takes a redeem script as a byte slice and appends it to
// the output at index outIndex.
func (p *Updater) AddOutRedeemScript(redeemScript []byte,
	outIndex int) error {

	p.Data.Outputs[outIndex].RedeemScript = redeemScript

	if err := p.Data.SanityCheck(); err != nil {
		return psbt.ErrInvalidPsbtFormat
	}

	return nil
}

// AddOutWitnessScript takes a witness script as a byte slice and appends it to
// the output at index outIndex.
func (p *Updater) AddOutWitnessScript(witnessScript []byte,
	outIndex int) error {

	p.Data.Outputs[outIndex].WitnessScript = witnessScript

	if err := p.Data.SanityCheck(); err != nil {
		return err
	}

	return nil
}

// AddInput adds input to underlying unsignedTx
func (p *Updater) AddInput(txInput *transaction.TxInput) {
	p.Data.UnsignedTx.AddInput(txInput)
	p.Data.Inputs = append(p.Data.Inputs, PInput{})
}

// AddOutput adds output to underlying unsignedTx
func (p *Updater) AddOutput(txOutput *transaction.TxOutput) {
	p.Data.UnsignedTx.AddOutput(txOutput)
	p.Data.Outputs = append(p.Data.Outputs, POutput{})
}

// AddIssuanceArgs is a struct encapsulating all the issuance data that
// can be attached to any specific transaction of the PSBT.
type AddIssuanceArgs struct {
	Precision    uint
	Contract     *transaction.IssuanceContract
	AssetAmount  uint64
	TokenAmount  uint64
	AssetAddress string
	TokenAddress string
}

func (arg AddIssuanceArgs) validate() error {
	if _, err := transaction.NewTxIssuance(
		arg.AssetAmount,
		arg.TokenAmount,
		arg.Precision,
		arg.Contract,
	); err != nil {
		return err
	}

	if len(arg.AssetAddress) <= 0 {
		return errors.New("missing destination address for asset to issue")
	}

	if _, err := address.DecodeType(arg.AssetAddress); err != nil {
		return err
	}

	if arg.TokenAmount > 0 {
		if len(arg.TokenAddress) <= 0 {
			return errors.New("missing destination address for token to issue")
		}
		if _, err := address.DecodeType(arg.TokenAddress); err != nil {
			return err
		}
	}
	if !arg.matchAddressTypes() {
		return errors.New(
			"asset and token destination addresses must both be confidential or " +
				"non-confidential",
		)
	}

	return nil
}

func (arg AddIssuanceArgs) matchAddressTypes() bool {
	if len(arg.TokenAddress) <= 0 {
		return true
	}

	a, _ := address.IsConfidential(arg.AssetAddress)
	b, _ := address.IsConfidential(arg.TokenAddress)
	// xnor -> return true only if a and b have the same value
	return !((a || b) && (!a || !b))
}

func (arg AddIssuanceArgs) tokenFlag() uint {
	if isConfidential, _ := address.IsConfidential(
		arg.AssetAddress,
	); isConfidential {
		return uint(ConfidentialReissuanceTokenFlag)
	}
	return uint(NonConfidentialReissuanceTokenFlag)
}

// AddIssuance adds an unblinded issuance to the transaction
func (p *Updater) AddIssuance(arg AddIssuanceArgs) error {
	if err := arg.validate(); err != nil {
		return err
	}

	if len(p.Data.UnsignedTx.Inputs) == 0 {
		return errors.New("transaction must contain at least one input")
	}

	issuance, _ := transaction.NewTxIssuance(
		arg.AssetAmount,
		arg.TokenAmount,
		arg.Precision,
		arg.Contract,
	)

	prevoutIndex, prevoutHash, inputIndex := findInputWithEmptyIssuance(p.Data)
	if inputIndex < 0 {
		return errors.New(
			"transaction does not contain any input with empty issuance",
		)
	}

	if err := issuance.GenerateEntropy(
		prevoutHash[:],
		prevoutIndex,
	); err != nil {
		return err
	}

	p.Data.UnsignedTx.Inputs[inputIndex].Issuance = &transaction.TxIssuance{
		AssetEntropy:       issuance.ContractHash,
		AssetAmount:        issuance.TxIssuance.AssetAmount,
		TokenAmount:        issuance.TxIssuance.TokenAmount,
		AssetBlindingNonce: issuance.TxIssuance.AssetBlindingNonce,
	}

	assetHash, err := issuance.GenerateAsset()
	if err != nil {
		return err
	}
	// prepend with a 0x01 prefix
	assetHash = append([]byte{0x01}, assetHash...)

	script, err := address.ToOutputScript(arg.AssetAddress)
	if err != nil {
		return err
	}

	output := transaction.NewTxOutput(
		assetHash,
		issuance.TxIssuance.AssetAmount,
		script,
	)
	p.AddOutput(output)

	if arg.TokenAmount > 0 {
		tokenHash, err := issuance.GenerateReissuanceToken(arg.tokenFlag())
		if err != nil {
			return err
		}
		tokenHash = append([]byte{byte(1)}, tokenHash...)
		script, err := address.ToOutputScript(arg.TokenAddress)
		if err != nil {
			return err
		}

		output := transaction.NewTxOutput(
			tokenHash,
			issuance.TxIssuance.TokenAmount,
			script,
		)
		p.AddOutput(output)
	}

	return nil
}

// AddReissuanceArgs defines the mandatory fields that one needs to pass to
// the AddReissuance method of the *Updater type
// 		PrevOutHash: the prevout hash of the token that will be added as input to the tx
//		PrevOutIndex: the prevout index of the token that will be added as input to the tx
//		PrevOutBlinder: the asset blinder used to blind the prevout token
//		WitnessUtxo: the prevout token in case it is a witness one
//		NonWitnessUtxo: the prevout tx that include the token output in case it is a non witness one
//		Entropy: the entropy used to generate token and asset
//		AssetAmount: the amount of asset to re-issue
//		TokenAmount: the same unblinded amount of the prevout token
//		AssetAddress: the destination address of the re-issuing asset
//		TokenAddress: the destination address of the re-issuance token
type AddReissuanceArgs struct {
	PrevOutHash    string
	PrevOutIndex   uint32
	PrevOutBlinder []byte
	WitnessUtxo    *transaction.TxOutput
	NonWitnessUtxo *transaction.Transaction
	Entropy        string
	AssetAmount    uint64
	AssetAddress   string
	TokenAmount    uint64
	TokenAddress   string
}

func (arg AddReissuanceArgs) validate() error {
	if arg.WitnessUtxo == nil && arg.NonWitnessUtxo == nil {
		return errors.New("either WitnessUtxo or NonWitnessUtxo must be defined")
	}

	if buf, err := hex.DecodeString(arg.PrevOutHash); err != nil || len(buf) != 32 {
		return errors.New("invalid input hash")
	}

	if arg.NonWitnessUtxo != nil {
		hash := arg.NonWitnessUtxo.TxHash()
		if hex.EncodeToString(elementsutil.ReverseBytes(hash[:])) != arg.PrevOutHash {
			return errors.New("input and non witness utxo hashes must match")
		}
	}

	// it's mandatory for the token prevout to be confidential. This because the
	// prevout value blinder will be used as the reissuance's blinding nonce to
	// prove that the spender actually owns and can unblind the token output.
	if !arg.isPrevoutConfidential() {
		return errors.New(
			"token prevout must be confidential. You must blind your token by " +
				"sending it to yourself in a confidential transaction if you want " +
				"be able to reissue the relative asset",
		)
	}

	if len(arg.PrevOutBlinder) != 32 {
		return errors.New("invalid input blinder")
	}

	if buf, err := hex.DecodeString(arg.Entropy); err != nil || len(buf) != 32 {
		return errors.New("invalid asset entropy")
	}

	if arg.AssetAmount <= 0 {
		return errors.New("invalid asset amount")
	}

	if arg.TokenAmount <= 0 {
		return errors.New("invalid token amount")
	}

	if len(arg.AssetAddress) <= 0 {
		return errors.New("invalid destination address for asset")
	}
	if _, err := address.DecodeType(arg.AssetAddress); err != nil {
		return err
	}
	if len(arg.TokenAddress) <= 0 {
		return errors.New("invalid destination address for token")
	}
	if _, err := address.DecodeType(arg.TokenAddress); err != nil {
		return err
	}
	if !arg.areAddressesConfidential() {
		return errors.New("asset and token address must be both confidential")
	}

	return nil
}

func (arg AddReissuanceArgs) isPrevoutConfidential() bool {
	if arg.WitnessUtxo != nil {
		return arg.WitnessUtxo.IsConfidential()
	}
	return arg.NonWitnessUtxo.Outputs[arg.PrevOutIndex].IsConfidential()
}

func (arg AddReissuanceArgs) areAddressesConfidential() bool {
	a, _ := address.IsConfidential(arg.AssetAddress)
	b, _ := address.IsConfidential(arg.TokenAddress)
	return a && b
}

// AddReissuance takes care of adding an input (the prevout token) and 2
// outputs to the partial transaction. It also creates a new (re)issuance with
// the provided entropy, blinder and amounts and attaches it to the new input.
// NOTE: This transaction must be blinded later so that a new token blinding
// nonce is generated for the new token output
func (p *Updater) AddReissuance(arg AddReissuanceArgs) error {
	if err := arg.validate(); err != nil {
		return err
	}

	if len(p.Data.Inputs) == 0 {
		return errors.New(
			"transaction must contain at least one input before adding a reissuance",
		)
	}

	prevoutHash, _ := hex.DecodeString(arg.PrevOutHash)
	prevoutHash = elementsutil.ReverseBytes(prevoutHash)
	prevoutIndex := arg.PrevOutIndex

	// add input
	tokenInput := transaction.NewTxInput(prevoutHash, prevoutIndex)
	p.AddInput(tokenInput)
	inputIndex := len(p.Data.Inputs) - 1
	if arg.WitnessUtxo != nil {
		p.AddInWitnessUtxo(arg.WitnessUtxo, inputIndex)
	} else {
		p.AddInNonWitnessUtxo(arg.NonWitnessUtxo, inputIndex)
	}

	entropy, _ := hex.DecodeString(arg.Entropy)
	entropy = elementsutil.ReverseBytes(entropy)
	issuance := transaction.NewTxIssuanceFromEntropy(entropy)

	assetHash, _ := issuance.GenerateAsset()
	assetHash = append([]byte{0x01}, assetHash...)
	assetScript, _ := address.ToOutputScript(arg.AssetAddress)
	assetAmount, _ := elementsutil.SatoshiToElementsValue(arg.AssetAmount)

	tokenHash, _ := issuance.GenerateReissuanceToken(
		ConfidentialReissuanceTokenFlag,
	)
	tokenHash = append([]byte{0x01}, tokenHash...)
	tokenScript, _ := address.ToOutputScript(arg.TokenAddress)
	tokenAmount, _ := elementsutil.SatoshiToElementsValue(arg.TokenAmount)

	// add outputs
	reissuanceOutput := transaction.NewTxOutput(
		assetHash,
		assetAmount,
		assetScript,
	)
	p.AddOutput(reissuanceOutput)

	// and the token output
	tokenOutput := transaction.NewTxOutput(
		tokenHash,
		tokenAmount,
		tokenScript,
	)
	p.AddOutput(tokenOutput)

	// add the (re)issuance to the token input. The token amount of the issuance
	// must not be defined for reissunces.
	p.Data.UnsignedTx.Inputs[inputIndex].Issuance = &transaction.TxIssuance{
		AssetBlindingNonce: arg.PrevOutBlinder,
		TokenAmount:        []byte{0x00},
		AssetAmount:        assetAmount,
		AssetEntropy:       issuance.TxIssuance.AssetEntropy,
	}

	return nil
}

func findInputWithEmptyIssuance(p *Pset) (uint32, []byte, int) {
	for i, in := range p.UnsignedTx.Inputs {
		if !in.HasAnyIssuance() {
			return in.Index, in.Hash[:], i
		}
	}
	return 0, nil, -1
}
