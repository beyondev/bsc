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
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
)

// TestStateDiffSync checks that per-block diff import and segment import reach
// the same state as execution, that a wrong diff is refused, and that blocks
// imported from diffs never fire the event that triggers voting.
func TestStateDiffSync(t *testing.T) {
	w := newDiffWorkload(t, diffWorkloadConfig{Blocks: 40, TxsPerBlock: 60, Prefill: 2000, Mix: mixMainnetLike})

	// Execution baseline.
	exec := w.newSyncChain(t, t.TempDir())
	defer exec.Stop()
	if _, err := exec.InsertChain(w.blocks); err != nil {
		t.Fatalf("exec import: %v", err)
	}
	want := exec.CurrentBlock().Root

	// Per-block diffs; no HighestVerifiedBlockEvent may be sent.
	perBlock := w.newSyncChain(t, t.TempDir())
	defer perBlock.Stop()
	events := make(chan HighestVerifiedBlockEvent, len(w.blocks))
	sub := perBlock.SubscribeHighestVerifiedHeaderEvent(events)
	defer sub.Unsubscribe()
	if n, err := perBlock.InsertChainWithDiffs(w.blocks, w.payloads(false)); err != nil {
		t.Fatalf("diff import stopped at %d: %v", n, err)
	}
	if got := perBlock.CurrentBlock().Root; got != want {
		t.Fatalf("per-block diff root %x, want %x", got, want)
	}
	select {
	case ev := <-events:
		t.Fatalf("diff-imported block %d fired HighestVerifiedBlockEvent", ev.Header.Number)
	case <-time.After(100 * time.Millisecond):
	}
	for _, b := range w.blocks {
		if rawdb.ReadRawReceipts(perBlock.db, b.Hash(), b.NumberU64()) == nil {
			t.Fatalf("receipts of block %d missing", b.NumberU64())
		}
	}

	// Segments of 16, with attestations.
	seg := w.newSyncChain(t, t.TempDir())
	defer seg.Stop()
	payloads := w.payloads(true)
	for i := 0; i < len(w.blocks); i += 16 {
		end := min(i+16, len(w.blocks))
		if err := seg.InsertSegmentWithDiff(w.blocks[i:end], payloads[i:end], true); err != nil {
			t.Fatalf("segment %d: %v", i, err)
		}
	}
	if got := seg.CurrentBlock().Root; got != want {
		t.Fatalf("segment root %x, want %x", got, want)
	}

	// A tampered diff is refused at the block it corrupts.
	bad := w.newSyncChain(t, t.TempDir())
	defer bad.Stop()
	tampered := w.payloads(false)
	tampered[5] = tamperFinalWrite(tampered[5])
	n, err := bad.InsertChainWithDiffs(w.blocks, tampered)
	if !errors.Is(err, ErrDiffRejected) || n != 5 {
		t.Fatalf("tampered diff: imported %d, err %v", n, err)
	}
}

// tamperFinalWrite returns a copy of the payload whose diff writes a wrong
// value into the first storage slot it touches.
func tamperFinalWrite(p *BlockDiffPayload) *BlockDiffPayload {
	cp := *p
	cp.Diff = copyDiff(p.Diff)
	for i := range cp.Diff.Accounts {
		if len(cp.Diff.Accounts[i].Storage) > 0 {
			cp.Diff.Accounts[i].Storage[0].Value = common.HexToHash("0xbad")
			return &cp
		}
	}
	panic("no storage write to tamper with")
}

func copyDiff(d *types.StateDiff) *types.StateDiff {
	out := &types.StateDiff{Accounts: make([]types.DiffAccount, len(d.Accounts))}
	for i, a := range d.Accounts {
		a.Storage = append([]types.DiffSlot(nil), a.Storage...)
		out.Accounts[i] = a
	}
	return out
}
