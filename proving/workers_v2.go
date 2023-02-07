package proving

import (
	"context"
	"log"
	"math"

	"github.com/zeebo/blake3"
)

const N = 256 * 1024 * 1024 * 1024
const B = 16
const numNonces = 20

type IndexReporterNew interface {
	Report(ctx context.Context, nonce uint32, idx uint64) (stop bool)
}

func workNewBlake(ctx context.Context, data <-chan *batch, reporter IndexReporterNew, ch Challenge, difficulty []byte) {
	// Params:
	// Blake's output size in bits
	const m = 512
	// dd: |d| = log2(N) - log2(B). Assumed both N and B are power of 2.
	dd := uint(math.Log2(N) - math.Log2(B))
	// numOuts = ceil(numNonces * |d| / m )
	numOuts := uint8(math.Ceil(float64(numNonces*dd) / m))

	h, err := blake3.NewKeyed(ch)
	if err != nil {
		log.Panicf("Failed to create new blake3 Hasher: %v", err)
	}

	out := make([]byte, 128)

	for batch := range data {
		index := batch.Index
		labels := batch.Data
		for len(labels) > 0 {
			block := labels[:B]
			labels = labels[B:]

			for i := uint8(0); i < numOuts; i++ {
				h.Reset()
				h.Write(block)
				h.Write([]byte{i})
				d := h.Digest()
				d.Read(out[i*64 : i*64+64])
			}

			// bits := bitstream.NewReader(bytes.NewReader(out))
			// for j := 0; j < numNonces; j++ {
			// 	_, err := bits.Read(dd)
			// 	if err != nil {
			// 		log.Panicf("Failed to read next %d bits of blake3 hash out: %v", dd, err)
			// 	}

			// 	// if bytes.Compare(outBlock, difficulty) <= 0 {
			// 	// 	if stop := reporter.Report(ctx, uint32(j), index); stop {
			// 	// 		batch.Release()
			// 	// 		return
			// 	// 	}
			// 	// }
			// }
			index++
		}
		batch.Release()
	}
}
