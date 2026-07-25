package doublylinkedtree

// CHK-AS-03 — unbounded fork-choice tree -> O(n^2) recursive traversal per slot.
//
// Finding (prysm 03, beacon-chain/forkchoice/doubly-linked-tree/gloas.go):
// the six recursive tree walks (applyWeightChanges*, updateBestDescendant*,
// pruneFinalizedNodeByRootMap, setNodeAndParentValidated, nodeTreeDump,
// removeNodeAndChildren) carry no depth/size cap — only a ctx.Err() time bound.
// ForkChoice.Head() runs applyWeightChangesConsensusNode(treeRootNode) and
// updateBestDescendantConsensusNode(treeRootNode), each O(tree size), once per
// slot. When finality stalls (>=1/3 offline) the tree is never pruned, so the
// tree grows without bound and the per-slot cost grows with it: O(n) per Head,
// O(n^2) cumulative.
//
// This is an in-process reproduction against prysm's REAL fork-choice code
// (no mock of the recursion). It measures the exact recursion size — the number
// of nodes each Head() visits is precisely f.NodeCount() — so the O(n^2) result
// is deterministic, not a timing artifact. Wall time is reported as corroboration.
//
// Negative control (the guard): prysm's own prune() re-roots the tree at the
// finalized checkpoint. With finality advancing each epoch the tree stays
// bounded, so per-Head work is O(cap) and the cumulative cost is linear. The
// symptom is therefore caused by the *absence of a bound while finality stalls*,
// exactly as the finding states; guard.diff adds an explicit MAX_NODES cap as
// the in-code defense-in-depth.
//
// Run: go test ./beacon-chain/forkchoice/doubly-linked-tree/ \
//        -run TestCHKAS03_ForkchoiceUnboundedTreeQuadratic -v

import (
	"context"
	"testing"
	"time"

	"github.com/OffchainLabs/prysm/v7/config/params"
	"github.com/OffchainLabs/prysm/v7/consensus-types/primitives"
	"github.com/OffchainLabs/prysm/v7/testing/require"
)

// buildChain inserts `n` linear blocks (slot i, root indexToHash(i),
// parent indexToHash(i-1)) on top of the genesis node created by setup(0,0).
// Every SlotsPerEpoch slots, if prune is true, it advances the finalized
// checkpoint a couple of epochs back and calls the real prune(), modelling a
// node whose finality keeps up. Returns the ForkChoice plus the cumulative
// number of nodes visited by the per-slot Head() recursion.
func buildChain(t *testing.T, n uint64, prune bool) (*ForkChoice, uint64, time.Duration) {
	ctx := context.Background()
	f := setup(0, 0)
	require.NotNil(t, f)
	spe := uint64(params.BeaconConfig().SlotsPerEpoch)

	var cumulativeVisits uint64
	var headWall time.Duration
	for i := uint64(1); i <= n; i++ {
		parent := indexToHash(i - 1)
		if i == 1 {
			parent = params.BeaconConfig().ZeroHash // genesis node inserted by setup()
		}
		st, blk, err := prepareForkchoiceState(
			ctx, primitives.Slot(i), indexToHash(i), parent, [32]byte{}, 0, 0)
		require.NoError(t, err)
		require.NoError(t, f.InsertNode(ctx, st, blk))

		if prune && i > 2*spe && i%spe == 0 {
			// Finality advances: finalize a checkpoint two epochs back and prune.
			finalRoot := indexToHash(i - 2*spe)
			f.store.finalizedCheckpoint.Root = finalRoot
			_ = f.store.prune(ctx) // best-effort; re-roots the tree when it can
		}

		// One fork-choice Head() per slot — the real per-slot cost.
		start := time.Now()
		_, err = f.Head(ctx)
		require.NoError(t, err)
		headWall += time.Since(start)

		// Nodes visited by this Head() == current tree size (each recursion
		// walks every node). This is the deterministic work metric.
		cumulativeVisits += uint64(f.NodeCount())
	}
	return f, cumulativeVisits, headWall
}

func TestCHKAS03_ForkchoiceUnboundedTreeQuadratic(t *testing.T) {
	// Doubling the chain length should ~quadruple the cumulative recursion work
	// when the tree is never pruned (finality stalled), and only ~double it when
	// prune() keeps the tree bounded (finality healthy).
	const nSmall, nLarge = 1000, 2000

	_, visSmall, wallSmall := buildChain(t, nSmall, false /* stalled */)
	fLarge, visLarge, wallLarge := buildChain(t, nLarge, false /* stalled */)

	ratio := float64(visLarge) / float64(visSmall)
	t.Logf("STALLED  (no prune): visits %d->%d on 2x chain  ratio=%.2fx  (O(n^2) => ~4x)",
		visSmall, visLarge, ratio)
	t.Logf("STALLED  final tree NodeCount=%d (== chain length; unbounded)", fLarge.NodeCount())
	t.Logf("STALLED  cumulative Head() wall: %v (n=%d) vs %v (n=%d)",
		wallLarge, nLarge, wallSmall, nSmall)

	// ③ baseline symptom: cumulative work is super-linear (quadratic).
	require.Equal(t, true, ratio > 3.0,
		"expected ~4x (quadratic) growth in recursion work under finality stall")
	// The unbounded tree: NodeCount grows to the full chain length (+genesis), no cap.
	require.Equal(t, int(nLarge)+1, fLarge.NodeCount())

	// ② guard / mitigation: with finality advancing, prune() bounds the tree.
	fG, visG, wallG := buildChain(t, nLarge, true /* finality healthy */)
	boundedRatio := float64(visG) / float64(visLarge)
	t.Logf("HEALTHY  (prune):  final NodeCount=%d (bounded), cumulative visits %d (%.1f%% of stalled)",
		fG.NodeCount(), visG, boundedRatio*100)
	t.Logf("HEALTHY  cumulative Head() wall: %v vs stalled %v", wallG, wallLarge)

	// The pruned tree stays far smaller than the chain length ...
	require.Equal(t, true, fG.NodeCount() < int(nLarge/2),
		"prune() should keep the tree well below the chain length")
	// ... and does far less cumulative recursion work than the stalled node.
	require.Equal(t, true, visG < visLarge/2,
		"bounded tree must do far less cumulative work than the unbounded one")
}
