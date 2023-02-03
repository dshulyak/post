package proving

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"log"
	"sync"
	"sync/atomic"

	"github.com/dchest/siphash"
	"github.com/spacemeshos/sha256-simd"
	"github.com/spaolacci/murmur3"
	twmb "github.com/twmb/murmur3"
)

type batch struct {
	Data     []byte
	Index    uint64
	refCount atomic.Int32
	free     func(*batch)
}

func (b *batch) Release() {
	if b.refCount.Add(-1) == 0 {
		b.free(b)
	}
}

type IndexReporter interface {
	Report(context.Context, uint64) (stop bool)
}

type IndexConsumer struct {
	Indexes chan uint64
	passed  atomic.Uint32
	needed  uint32
}

func (c *IndexConsumer) Report(ctx context.Context, index uint64) bool {
	select {
	case c.Indexes <- index:
		return c.passed.Add(1) >= c.needed
	case <-ctx.Done():
		return true
	}
}

// produce reads from `reader` and distributes batches of data into `workerQueues`.
func produce(ctx context.Context, reader io.Reader, workerQeues []chan *batch) error {
	var bufferPool = sync.Pool{
		New: func() any {
			return make([]byte, 1024*1024)
		},
	}
	defer func() {
		for _, q := range workerQeues {
			close(q)
		}
	}()
	index := uint64(0)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		b := &batch{
			Data:  bufferPool.Get().([]byte),
			Index: index,
			free: func(b *batch) {
				bufferPool.Put(b.Data)
			},
		}
		n, err := reader.Read(b.Data)
		if err != nil {
			bufferPool.Put(b.Data)
			return nil
		}

		b.refCount.Add(int32(len(workerQeues)))
		for i := 0; i < len(workerQeues); i++ {
			select {
			case workerQeues[i] <- b:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		index += uint64(n)
	}
}

// workAESCTR finds labels meeting difficulty using AES CTR way.
func workAESCTR(ctx context.Context, data <-chan *batch, reporter IndexReporter, labelSize uint8, ch Challenge, nonce uint32, difficulty []byte) {
	key := append([]byte{}, ch...)
	binary.LittleEndian.AppendUint32(key, nonce)
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	iv := make([]byte, aes.BlockSize)
	out := make([]byte, aes.BlockSize)
	in := make([]byte, aes.BlockSize)

	for batch := range data {
		index := batch.Index
		labels := batch.Data
		binary.BigEndian.PutUint64(iv[8:], index)
		ctr := cipher.NewCTR(c, iv)
		for len(labels) > 0 {
			label := labels[:labelSize]
			labels = labels[labelSize:]
			copy(in, label)

			ctr.XORKeyStream(out, in)
			if bytes.Compare(out, difficulty) <= 0 { // TODO: is it "less or equal" or just "less"?
				if stop := reporter.Report(ctx, index); stop {
					batch.Release()
					return
				}
			}
			index++
		}
		batch.Release()
	}
}

// workSha256 finds labels meeting difficulty using SHA256 way.
func workSha256(ctx context.Context, data <-chan *batch, reporter IndexReporter, labelSize uint8, ch Challenge, nonce uint32, difficulty []byte) {
	// Pre-initialize SHA256 digest
	digest := sha256.New().(*sha256.Digest)
	digest.Write(ch)
	indexB := make([]byte, 8)
	nb := make([]byte, 4)
	binary.LittleEndian.PutUint32(nb, nonce)
	digest.Write(nb)
	var hb [sha256.Size]byte

	for batch := range data {
		index := batch.Index
		labels := batch.Data
		for len(labels) > 0 {
			label := labels[:labelSize]
			labels = labels[labelSize:]

			// Make a copy of digest
			s := *digest

			binary.LittleEndian.PutUint64(indexB, index)
			s.Write(indexB)
			s.Write(label)
			s.CheckSumInto(&hb)
			// s.Sum(hb[:0])

			if bytes.Compare(hb[:], difficulty) <= 0 {
				if stop := reporter.Report(ctx, index); stop {
					batch.Release()
					return
				}
			}
			index++
		}
		batch.Release()
	}
}

// workTwmbMurmur3 finds labels meeting difficulty using github.com/twmb/murmur3.
func workTwmbMurmur3(ctx context.Context, data <-chan *batch, reporter IndexReporter, labelSize uint8, ch Challenge, nonce uint32, difficulty []byte) {
	workMurmur3(ctx, data, reporter, labelSize, ch, nonce, difficulty, twmb.Sum64)
}

// workMurmur3 finds labels meeting difficulty using Murmur3.
func workSpaolacciMurmur3(ctx context.Context, data <-chan *batch, reporter IndexReporter, labelSize uint8, ch Challenge, nonce uint32, difficulty []byte) {
	workMurmur3(ctx, data, reporter, labelSize, ch, nonce, difficulty, murmur3.Sum64)
}

type S64 = func(data []byte) uint64

func workMurmur3(ctx context.Context, data <-chan *batch, reporter IndexReporter, labelSize uint8, ch Challenge, nonce uint32, difficulty []byte, sum S64) {
	chLen := 32
	nonceLen := 4
	idLen := 8
	d := binary.BigEndian.Uint64(difficulty)
	size := chLen + nonceLen + idLen + int(labelSize)
	buffer := make([]byte, size)
	copy(buffer, ch[:chLen])
	binary.LittleEndian.PutUint32(buffer[chLen+8:], nonce)
	// binary.LittleEndian.PutUint16(buffer[chLen+idLen:], uint16(nonce))
	// buffer[chLen+idLen] = byte(nonce)

	for batch := range data {
		index := batch.Index
		labels := batch.Data
		for len(labels) > 0 {
			label := labels[:labelSize]
			labels = labels[labelSize:]

			binary.LittleEndian.PutUint64(buffer[chLen:], index)
			// NOTE: copy makes the bench 10% slower than using `buffer[chLen+nonceLen+8] = label[0]`.
			// TODO: Figure out why?
			copy(buffer[chLen+nonceLen+8:], label)
			// buffer[chLen+nonceLen+8] = label[0]

			value := sum(buffer)
			if value <= d {
				if stop := reporter.Report(ctx, index); stop {
					batch.Release()
					return
				}
			}
			index++
		}
		batch.Release()
	}
}

func workSiphash(ctx context.Context, data <-chan *batch, reporter IndexReporter, labelSize uint8, ch Challenge, nonce uint32, difficulty []byte) {
	nb := make([]byte, 4)
	binary.LittleEndian.PutUint32(nb, nonce)

	d := binary.BigEndian.Uint64(difficulty)

	h := siphash.New(ch)
	h.Write(nb)
	key0 := h.Sum64()

	for batch := range data {
		index := batch.Index
		labels := batch.Data
		for len(labels) > 0 {
			label := labels[:labelSize]
			labels = labels[labelSize:]

			value := siphash.Hash(key0, index, label)
			if value <= d {
				if stop := reporter.Report(ctx, index); stop {
					batch.Release()
					return
				}
			}
			index++
		}
		batch.Release()
	}
}
