// Copyright 2026 The bsc Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
)

// StateDiffRecorder receives the write set of every block written with state,
// both imported and locally mined.
type StateDiffRecorder func(block *types.Block, diff *types.StateDiff)

// SetStateDiffRecorder installs a recorder. It must be called before blocks are
// inserted.
func (bc *BlockChain) SetStateDiffRecorder(fn StateDiffRecorder) {
	bc.diffRecorder = fn
}

// BlockDiffPayload is what a diff-syncing node downloads for one block in
// addition to the block itself.
type BlockDiffPayload struct {
	Diff     *types.StateDiff
	Receipts types.Receipts // decoded from the storage encoding, derived fields not yet filled

	// Attested is the write-set hash covered by a validator attestation (a
	// Parlia side-channel attestation or a DX ExecCert). Zero means none.
	Attested common.Hash
}

// ErrDiffRejected wraps every reason a diff is refused. The block itself may
// still be valid; the caller falls back to executing it and stops using the
// peer that served the diff.
var ErrDiffRejected = errors.New("state diff rejected")

func rejectDiff(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrDiffRejected, fmt.Sprintf(format, args...))
}

// verifyDiffBlock runs the checks that do not depend on state: body, receipts
// against the header, and the attested write-set hash if present. The header
// itself is verified by the caller.
//
// Inside a segment the parent is not stored yet, so only the body contents are
// checked against the header instead of the full ValidateBody.
func (bc *BlockChain) verifyDiffBlock(block *types.Block, payload *BlockDiffPayload, inSegment bool) ([]*types.Log, error) {
	if inSegment {
		if err := validateBodyContents(block); err != nil {
			return nil, err
		}
	} else if err := bc.validator.ValidateBody(block); err != nil {
		return nil, err
	}
	receipts := payload.Receipts
	if len(receipts) != len(block.Transactions()) {
		return nil, rejectDiff("block %d: %d receipts for %d txs", block.NumberU64(), len(receipts), len(block.Transactions()))
	}
	if err := receipts.DeriveFields(bc.chainConfig, block.Hash(), block.NumberU64(), block.Time(), block.BaseFee(), nil, block.Transactions()); err != nil {
		return nil, rejectDiff("block %d: derive receipts: %v", block.NumberU64(), err)
	}
	for _, r := range receipts {
		r.Bloom = types.CreateBloom(r)
	}
	if types.MergeBloom(receipts) != block.Bloom() {
		return nil, rejectDiff("block %d: bloom mismatch", block.NumberU64())
	}
	if types.DeriveSha(receipts, trie.NewStackTrie(nil)) != block.ReceiptHash() {
		return nil, rejectDiff("block %d: receipt root mismatch", block.NumberU64())
	}
	if payload.Attested != (common.Hash{}) && payload.Diff.Hash() != payload.Attested {
		return nil, rejectDiff("block %d: write set does not match attestation", block.NumberU64())
	}
	var logs []*types.Log
	for _, r := range receipts {
		logs = append(logs, r.Logs...)
	}
	return logs, nil
}

// InsertChainWithDiffs imports consecutive blocks by applying their write sets
// instead of executing them, one block at a time. Every block's state root is
// recomputed and compared with its header, so a wrong diff is always caught at
// the block it corrupts.
//
// It returns the number of blocks imported. On ErrDiffRejected the block at
// that index was not written and the caller should execute it instead.
func (bc *BlockChain) InsertChainWithDiffs(blocks types.Blocks, payloads []*BlockDiffPayload) (int, error) {
	if len(blocks) != len(payloads) {
		return 0, errors.New("blocks and payloads differ in length")
	}
	if !bc.chainmu.TryLock() {
		return 0, errChainStopped
	}
	defer bc.chainmu.Unlock()

	for i, block := range blocks {
		if bc.NoTries() {
			return i, errors.New("diff import needs tries to verify state roots")
		}
		parent := bc.GetHeader(block.ParentHash(), block.NumberU64()-1)
		if parent == nil {
			return i, unknownAncestor(block)
		}
		if err := bc.engine.VerifyHeader(bc, block.Header()); err != nil {
			return i, err
		}
		logs, err := bc.verifyDiffBlock(block, payloads[i], false)
		if err != nil {
			return i, err
		}
		statedb, err := bc.StateAt(parent)
		if err != nil {
			return i, err
		}
		if err := bc.applyAndCheckRoot(statedb, block, payloads[i].Diff); err != nil {
			return i, err
		}
		if _, err := bc.writeBlockAndSetHeadOpts(block, payloads[i].Receipts, logs, statedb, nil, false); err != nil {
			return i, err
		}
	}
	return len(blocks), nil
}

// InsertSegmentWithDiff imports consecutive blocks by merging their write sets
// and computing a single state root at the end of the segment.
//
// Only the final root is checked against a header. Without attestations, a
// diff that writes a wrong value in one block and restores it in a later block
// passes: the final state is right but the per-block writes are not. With
// requireAttested set, every block's write set must match its attested hash,
// which closes that gap.
//
// Intermediate blocks are stored with their receipts but without state; only
// the last block of the segment has state.
func (bc *BlockChain) InsertSegmentWithDiff(blocks types.Blocks, payloads []*BlockDiffPayload, requireAttested bool) error {
	if len(blocks) == 0 || len(blocks) != len(payloads) {
		return errors.New("bad segment")
	}
	if !bc.chainmu.TryLock() {
		return errChainStopped
	}
	defer bc.chainmu.Unlock()

	if bc.NoTries() {
		return errors.New("diff import needs tries to verify state roots")
	}
	first := blocks[0]
	parent := bc.GetHeader(first.ParentHash(), first.NumberU64()-1)
	if parent == nil {
		return unknownAncestor(first)
	}
	if bc.CurrentBlock().Hash() != parent.Hash() {
		return errors.New("segment must extend the current head")
	}
	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	abort, results := bc.engine.VerifyHeaders(bc, headers)
	defer close(abort)
	for range headers {
		if err := <-results; err != nil {
			return err
		}
	}
	allLogs := make([][]*types.Log, len(blocks))
	diffs := make([]*types.StateDiff, len(blocks))
	for i, block := range blocks {
		if i > 0 && block.ParentHash() != blocks[i-1].Hash() {
			return errors.New("segment not contiguous")
		}
		if requireAttested && payloads[i].Attested == (common.Hash{}) {
			return rejectDiff("block %d: missing attestation", block.NumberU64())
		}
		logs, err := bc.verifyDiffBlock(block, payloads[i], true)
		if err != nil {
			return err
		}
		allLogs[i] = logs
		diffs[i] = payloads[i].Diff
	}
	last := blocks[len(blocks)-1]
	statedb, err := bc.StateAt(parent)
	if err != nil {
		return err
	}
	if err := bc.applyAndCheckRoot(statedb, last, types.MergeStateDiffs(diffs)); err != nil {
		return err
	}
	// Intermediate blocks: body, receipts and total difficulty, no state.
	ptd := bc.GetTd(parent.Hash(), parent.Number.Uint64())
	if ptd == nil {
		return unknownAncestor(first)
	}
	td := new(big.Int).Set(ptd) // the cached value must not be modified
	batch := bc.db.NewBatch()
	for i, block := range blocks[:len(blocks)-1] {
		td.Add(td, block.Difficulty())
		rawdb.WriteTd(batch, block.Hash(), block.NumberU64(), td)
		rawdb.WriteBlock(batch, block)
		rawdb.WriteReceipts(batch, block.Hash(), block.NumberU64(), payloads[i].Receipts)
		rawdb.WriteCanonicalHash(batch, block.Hash(), block.NumberU64())
	}
	if err := batch.Write(); err != nil {
		return err
	}
	if len(blocks) > 1 {
		bc.writeHeadBlock(blocks[len(blocks)-2])
	}
	_, err = bc.writeBlockAndSetHeadOpts(last, payloads[len(blocks)-1].Receipts, allLogs[len(blocks)-1], statedb, nil, false)
	return err
}

func (bc *BlockChain) applyAndCheckRoot(statedb *state.StateDB, block *types.Block, diff *types.StateDiff) error {
	noStorageWiping := bc.chainConfig.IsCancun(block.Number(), block.Time())
	if !bc.cfg.NoPrefetch {
		statedb.StartPrefetcher("diff", nil)
		defer statedb.StopPrefetcher()
	}
	if err := statedb.ApplyStateDiff(diff, noStorageWiping); err != nil {
		return rejectDiff("block %d: %v", block.NumberU64(), err)
	}
	if err := statedb.Error(); err != nil {
		// A local read failure is not the peer's fault.
		return err
	}
	root := statedb.IntermediateRoot(bc.chainConfig.IsEIP158(block.Number()))
	if err := statedb.Error(); err != nil {
		return err
	}
	if root != block.Root() {
		return rejectDiff("block %d: state root mismatch (header %x, diff %x)", block.NumberU64(), block.Root(), root)
	}
	return nil
}

// validateBodyContents checks that transactions, uncles and withdrawals match
// the header roots.
func validateBodyContents(block *types.Block) error {
	header := block.Header()
	if hash := types.DeriveSha(block.Transactions(), trie.NewStackTrie(nil)); hash != header.TxHash {
		return fmt.Errorf("transaction root hash mismatch: have %x, want %x", hash, header.TxHash)
	}
	if hash := types.CalcUncleHash(block.Uncles()); hash != header.UncleHash {
		return fmt.Errorf("uncle root hash mismatch: have %x, want %x", hash, header.UncleHash)
	}
	if header.WithdrawalsHash != nil {
		if block.Withdrawals() == nil {
			return errors.New("missing withdrawals in block body")
		}
		if hash := types.DeriveSha(block.Withdrawals(), trie.NewStackTrie(nil)); hash != *header.WithdrawalsHash {
			return fmt.Errorf("withdrawals root hash mismatch: have %x, want %x", hash, *header.WithdrawalsHash)
		}
	}
	return nil
}

func unknownAncestor(block *types.Block) error {
	return fmt.Errorf("%w: block %d parent %x", consensus.ErrUnknownAncestor, block.NumberU64(), block.ParentHash())
}
