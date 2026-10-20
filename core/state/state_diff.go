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

package state

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// StateDiff returns the block-level write set accumulated in the state since
// the last commit. It must be called after the block is finalised (for example
// after IntermediateRoot) and before Commit, which clears the pending storage
// and the mutation set it reads.
func (s *StateDB) StateDiff() *types.StateDiff {
	diff := &types.StateDiff{Accounts: make([]types.DiffAccount, 0, len(s.mutations))}
	for addr, op := range s.mutations {
		prev, destructed := s.stateObjectsDestruct[addr]
		existedBefore := destructed && prev.origin != nil
		if op.isDelete() {
			// Created and deleted within the block: nothing changed.
			if !existedBefore {
				continue
			}
			diff.Accounts = append(diff.Accounts, types.DiffAccount{Address: addr, Destructed: true, Deleted: true})
			continue
		}
		obj := s.stateObjects[addr]
		if obj == nil {
			continue
		}
		a := types.DiffAccount{
			Address:     addr,
			Destructed:  existedBefore,
			Nonce:       obj.data.Nonce,
			Balance:     obj.data.Balance.Clone(),
			CodeChanged: obj.dirtyCode,
		}
		if obj.dirtyCode {
			a.Code = common.CopyBytes(obj.code)
		}
		for key, val := range obj.pendingStorage {
			if existedBefore {
				// Recreated account: the pre-block storage is wiped, so every
				// non-zero slot of the new object is a write.
				if val == (common.Hash{}) {
					continue
				}
			} else if val == obj.originStorage[key] {
				continue
			}
			a.Storage = append(a.Storage, types.DiffSlot{Key: key, Value: val})
		}
		diff.Accounts = append(diff.Accounts, a)
	}
	diff.Sort()
	return diff
}

// ApplyStateDiff writes a block write set into the state without executing the
// block. The caller computes IntermediateRoot afterwards and compares it with
// the header root; any mismatch means the diff is wrong.
//
// noStorageWiping mirrors the Cancun rule enforced at commit time: a
// pre-existing account with storage may not be destructed. The check runs here
// so that a bad diff is rejected before anything is written to disk.
func (s *StateDB) ApplyStateDiff(diff *types.StateDiff, noStorageWiping bool) error {
	if err := checkDiffStructure(diff); err != nil {
		return err
	}
	if s.prefetcher != nil {
		s.prefetchDiff(diff)
	}
	destructed := false
	for i := range diff.Accounts {
		a := &diff.Accounts[i]
		if !a.Destructed {
			continue
		}
		obj := s.getStateObject(a.Address)
		if obj == nil {
			return fmt.Errorf("diff destructs missing account %x", a.Address)
		}
		if noStorageWiping && obj.data.Root != types.EmptyRootHash {
			return fmt.Errorf("diff wipes storage of %x", a.Address)
		}
		s.SelfDestruct(a.Address)
		destructed = true
	}
	if destructed {
		s.Finalise(true)
	}
	for i := range diff.Accounts {
		a := &diff.Accounts[i]
		if a.Deleted {
			continue
		}
		balance := a.Balance
		if balance == nil {
			return fmt.Errorf("diff account %x has no balance", a.Address)
		}
		s.SetNonce(a.Address, a.Nonce, tracing.NonceChangeUnspecified)
		s.SetBalance(a.Address, balance, tracing.BalanceChangeUnspecified)
		if a.CodeChanged {
			s.SetCode(a.Address, a.Code, tracing.CodeChangeUnspecified)
		}
		for _, slot := range a.Storage {
			s.SetState(a.Address, slot.Key, slot.Value)
		}
	}
	return nil
}

// prefetchDiff schedules every account and slot the diff touches on the trie
// prefetcher, so that the trie nodes are loaded concurrently while the diff is
// applied and are hot when the root is computed.
func (s *StateDB) prefetchDiff(diff *types.StateDiff) {
	addrs := make([]common.Address, len(diff.Accounts))
	for i := range diff.Accounts {
		addrs[i] = diff.Accounts[i].Address
	}
	if err := s.prefetcher.prefetch(common.Hash{}, s.originalRoot, common.Address{}, addrs, nil, false); err != nil {
		log.Error("Failed to prefetch diff accounts", "err", err)
	}
	for i := range diff.Accounts {
		a := &diff.Accounts[i]
		if a.Destructed || len(a.Storage) == 0 {
			continue
		}
		obj := s.getStateObject(a.Address)
		if obj == nil || obj.data.Root == types.EmptyRootHash {
			continue
		}
		keys := make([]common.Hash, len(a.Storage))
		for j, slot := range a.Storage {
			keys[j] = slot.Key
		}
		if err := s.prefetcher.prefetch(obj.addrHash(), obj.data.Root, a.Address, nil, keys, false); err != nil {
			log.Error("Failed to prefetch diff slots", "addr", a.Address, "err", err)
		}
	}
}

func checkDiffStructure(diff *types.StateDiff) error {
	for i := range diff.Accounts {
		a := &diff.Accounts[i]
		if i > 0 && bytes.Compare(diff.Accounts[i-1].Address[:], a.Address[:]) >= 0 {
			return errors.New("diff accounts not strictly ascending")
		}
		if a.Deleted && (!a.Destructed || a.Nonce != 0 || (a.Balance != nil && !a.Balance.IsZero()) || a.CodeChanged || len(a.Storage) > 0) {
			return fmt.Errorf("deleted account %x carries fields", a.Address)
		}
		for j := 1; j < len(a.Storage); j++ {
			if bytes.Compare(a.Storage[j-1].Key[:], a.Storage[j].Key[:]) >= 0 {
				return fmt.Errorf("storage of %x not strictly ascending", a.Address)
			}
		}
	}
	return nil
}
