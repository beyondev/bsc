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

package types

import (
	"bytes"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// StateDiff is the block-level write set of a block: the final value of every
// account and storage slot the block modified. It is the "post-value" half of
// an EIP-7928 block access list, without read sets or per-transaction indices.
type StateDiff struct {
	Accounts []DiffAccount // strictly ascending by address
}

// DiffAccount is the final state of one modified account.
type DiffAccount struct {
	Address     common.Address
	Destructed  bool // an account that existed before the block was destructed (storage wiped), possibly recreated afterwards
	Deleted     bool // the account does not exist at the end of the block; implies Destructed and no other fields
	Nonce       uint64
	Balance     *uint256.Int
	CodeChanged bool   // code was modified; Code may be empty
	Code        []byte // new code when CodeChanged
	Storage     []DiffSlot
}

// DiffSlot is the final value of one storage slot, keyed by the raw slot key.
type DiffSlot struct {
	Key   common.Hash
	Value common.Hash
}

// Sort orders accounts by address and slots by key.
func (d *StateDiff) Sort() {
	slices.SortFunc(d.Accounts, func(a, b DiffAccount) int { return bytes.Compare(a.Address[:], b.Address[:]) })
	for i := range d.Accounts {
		slices.SortFunc(d.Accounts[i].Storage, func(a, b DiffSlot) int { return bytes.Compare(a.Key[:], b.Key[:]) })
	}
}

// Hash returns the keccak256 hash of the RLP encoding. It is the value a
// write-set attestation signs over.
func (d *StateDiff) Hash() common.Hash {
	enc, _ := rlp.EncodeToBytes(d)
	return crypto.Keccak256Hash(enc)
}

// Keys returns the number of accounts and storage slots in the diff.
func (d *StateDiff) Keys() (accounts int, slots int) {
	for i := range d.Accounts {
		slots += len(d.Accounts[i].Storage)
	}
	return len(d.Accounts), slots
}

// MergeStateDiffs folds consecutive block diffs into one diff that takes the
// parent state of the first block to the post state of the last block. Later
// writes override earlier ones; a destruction drops the storage accumulated
// before it.
func MergeStateDiffs(diffs []*StateDiff) *StateDiff {
	type acc struct {
		DiffAccount
		slots map[common.Hash]common.Hash
	}
	merged := make(map[common.Address]*acc)
	for _, d := range diffs {
		for i := range d.Accounts {
			a := &d.Accounts[i]
			m, ok := merged[a.Address]
			if !ok {
				m = &acc{slots: make(map[common.Hash]common.Hash)}
				m.Address = a.Address
				merged[a.Address] = m
			}
			if a.Destructed {
				// The storage written before the destruction is gone. The
				// merged entry stays destructed so that the storage existing
				// before the segment is wiped as well.
				m.Destructed = true
				m.slots = make(map[common.Hash]common.Hash)
				m.Code, m.CodeChanged = nil, true
			}
			m.Deleted = a.Deleted
			if a.Deleted {
				m.Nonce, m.Balance, m.Code, m.CodeChanged = 0, nil, nil, false
				m.slots = make(map[common.Hash]common.Hash)
				continue
			}
			m.Nonce, m.Balance = a.Nonce, a.Balance
			if a.CodeChanged {
				m.Code, m.CodeChanged = a.Code, true
			}
			for _, s := range a.Storage {
				m.slots[s.Key] = s.Value
			}
		}
	}
	out := &StateDiff{Accounts: make([]DiffAccount, 0, len(merged))}
	for _, m := range merged {
		a := m.DiffAccount
		if a.Deleted {
			a.Destructed = true
		}
		if !a.Destructed && a.CodeChanged && a.Code == nil {
			a.Code = []byte{}
		}
		a.Storage = make([]DiffSlot, 0, len(m.slots))
		for k, v := range m.slots {
			// Zero slots matter only when they overwrite a pre-existing value;
			// after a destruction everything starts at zero anyway.
			if a.Destructed && v == (common.Hash{}) {
				continue
			}
			a.Storage = append(a.Storage, DiffSlot{Key: k, Value: v})
		}
		out.Accounts = append(out.Accounts, a)
	}
	out.Sort()
	return out
}
