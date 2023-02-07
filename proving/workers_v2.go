package proving

import (
	"context"

	"github.com/zeebo/blake3"
)

const N = 256 * 1024 * 1024 * 1024
const B = 16
const numNonces = 20

type IndexReporterNew interface {
	Report(ctx context.Context, nonce uint32, idx uint64) (stop bool)
}

func le40(b []byte) uint64 {
	_ = b[4]
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32
}

func workNewBlake(ctx context.Context, data <-chan *batch, reporter IndexReporterNew, ch Challenge, difficulty []byte) {
	// Params:
	// Blake's output size in bits
	const m = 512
	const dsize = 5 // padded to 40 bits

	dval := le40(difficulty)
	h := blake3.New()
	out := make([]byte, dsize*numNonces)

	for batch := range data {
		index := batch.Index
		labels := batch.Data
		for len(labels) > 0 {
			block := labels[:B]
			labels = labels[B:]

			h.Reset()
			h.Write(ch)
			h.Write(block)
			h.Write([]byte{0})
			d := h.Digest()
			d.Read(out) // streams variable length output

			for i := 0; i < numNonces; i++ {
				// padded to 5 bytes to avoid bit arithmetic
				if le40(out[i*dsize:]) <= dval {
					reporter.Report(context.TODO(), uint32(i), index)
				}
			}
			index++
		}
		batch.Release()
	}
}
