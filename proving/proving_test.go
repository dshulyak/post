package proving

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"testing"

	"github.com/spacemeshos/sha256-simd"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/spacemeshos/post/config"
	"github.com/spacemeshos/post/initialization"
	"github.com/spacemeshos/post/shared"
	"github.com/spacemeshos/post/verifying"
)

var (
	NewInitializer = initialization.NewInitializer
	CPUProviderID  = initialization.CPUProviderID
)

func getTestConfig(t *testing.T) (config.Config, config.InitOpts) {
	cfg := config.DefaultConfig()
	cfg.LabelsPerUnit = 1 << 12

	opts := config.DefaultInitOpts()
	opts.DataDir = t.TempDir()
	opts.NumUnits = cfg.MinNumUnits
	opts.ComputeProviderID = int(CPUProviderID())

	return cfg, opts
}

type testLogger struct {
	shared.Logger

	t testing.TB
}

func (l testLogger) Info(msg string, args ...any)  { l.t.Logf("\tINFO\t"+msg, args...) }
func (l testLogger) Debug(msg string, args ...any) { l.t.Logf("\tDEBUG\t"+msg, args...) }
func (l testLogger) Error(msg string, args ...any) { l.t.Logf("\tERROR\t"+msg, args...) }

func TestProver_GenerateProof(t *testing.T) {
	// TODO(moshababo): tests should range through `cfg.BitsPerLabel` as well.
	r := require.New(t)
	log := testLogger{t: t}

	// for numUnits := uint32(config.DefaultMinNumUnits); numUnits < 6; numUnits++ {
	// numUnits := uint32(5242880)
	numUnits := uint32(2000)
	t.Run(fmt.Sprintf("numUnits=%d", numUnits), func(t *testing.T) {
		t.Parallel()

		nodeId := make([]byte, 32)
		commitmentAtxId := make([]byte, 32)
		ch := make(Challenge, 32)
		cfg := config.DefaultConfig()
		cfg.LabelsPerUnit = 1 << 12
		cfg.MaxNumUnits = 5242880

		opts := config.DefaultInitOpts()
		opts.ComputeProviderID = int(CPUProviderID())
		opts.NumUnits = numUnits
		// opts.DataDir = t.TempDir()
		opts.DataDir = "./test-data/8MB"
		// opts.DataDir = "./test-data/20GB"
		opts.MaxFileSize = 4294967296
		// opts.MaxFileSize = 21474836480

		init, err := NewInitializer(
			initialization.WithNodeId(nodeId),
			initialization.WithCommitmentAtxId(commitmentAtxId),
			initialization.WithConfig(cfg),
			initialization.WithInitOpts(opts),
			initialization.WithLogger(log),
		)
		r.NoError(err)
		r.NoError(init.Initialize(context.Background()))

		p, err := NewProver(cfg, opts.DataDir, nodeId, commitmentAtxId)
		r.NoError(err)
		p.SetLogger(log)

		binary.BigEndian.PutUint64(ch, uint64(opts.NumUnits))
		ch[7] = 128 // 96s

		// started := time.Now()
		proof, proofMetaData, err := p.GenerateProof(ch)
		// log.Info("Took: %s\n", time.Since(started))
		r.NoError(err, "numUnizts: %d", opts.NumUnits)
		r.NotNil(proof)
		r.NotNil(proofMetaData)

		r.Equal(nodeId, proofMetaData.NodeId)
		r.Equal(commitmentAtxId, proofMetaData.CommitmentAtxId)
		r.Equal(ch, proofMetaData.Challenge)
		r.Equal(cfg.BitsPerLabel, proofMetaData.BitsPerLabel)
		r.Equal(cfg.LabelsPerUnit, proofMetaData.LabelsPerUnit)
		r.Equal(opts.NumUnits, proofMetaData.NumUnits)
		r.Equal(cfg.K1, proofMetaData.K1)
		r.Equal(cfg.K2, proofMetaData.K2)

		numLabels := cfg.LabelsPerUnit * uint64(numUnits)
		indexBitSize := uint(shared.BinaryRepresentationMinBits(numLabels))
		r.Equal(shared.Size(indexBitSize, uint(p.cfg.K2)), uint(len(proof.Indices)))

		log.Info("numLabels: %v, indices size: %v\n", numLabels, len(proof.Indices))

		r.NoError(verifying.Verify(proof, proofMetaData))
	})
	// }
}

func BenchmarkProver_GenerateProof(t *testing.B) {
	r := require.New(t)
	log := testLogger{t: t}

	numUnits := uint32(4000)

	nodeId := make([]byte, 32)
	commitmentAtxId := make([]byte, 32)
	ch := make(Challenge, 32)
	cfg := config.DefaultConfig()
	cfg.LabelsPerUnit = 1 << 12
	cfg.MaxNumUnits = 5242880

	opts := config.DefaultInitOpts()
	opts.ComputeProviderID = int(CPUProviderID())
	opts.NumUnits = numUnits
	opts.DataDir = "./test-data/16MB"
	opts.MaxFileSize = 4294967296

	init, err := NewInitializer(
		initialization.WithNodeId(nodeId),
		initialization.WithCommitmentAtxId(commitmentAtxId),
		initialization.WithConfig(cfg),
		initialization.WithInitOpts(opts),
		initialization.WithLogger(log),
	)
	r.NoError(err)
	r.NoError(init.Initialize(context.Background()))

	p, err := NewProver(cfg, opts.DataDir, nodeId, commitmentAtxId)
	r.NoError(err)
	p.SetLogger(log)

	binary.BigEndian.PutUint64(ch, uint64(opts.NumUnits))

	proof, proofMetaData, err := p.GenerateProof(ch)

	numLabels := cfg.LabelsPerUnit * uint64(numUnits)
	indexBitSize := uint(shared.BinaryRepresentationMinBits(numLabels))
	r.Equal(shared.Size(indexBitSize, uint(p.cfg.K2)), uint(len(proof.Indices)))

	log.Info("numLabels: %v, indices size: %v\n", numLabels, len(proof.Indices))

	r.NoError(verifying.Verify(proof, proofMetaData))
}

func TestProver_GenerateProof_NotAllowed(t *testing.T) {
	r := require.New(t)

	nodeId := make([]byte, 32)
	commitmentAtxId := make([]byte, 32)

	ch := make(Challenge, 32)
	cfg, opts := getTestConfig(t)
	init, err := NewInitializer(
		initialization.WithNodeId(nodeId),
		initialization.WithCommitmentAtxId(commitmentAtxId),
		initialization.WithConfig(cfg),
		initialization.WithInitOpts(opts),
		initialization.WithLogger(testLogger{t: t}),
	)
	r.NoError(err)
	r.NoError(init.Initialize(context.Background()))

	// Attempt to generate proof with different `nodeId`.
	newNodeId := make([]byte, 32)
	copy(newNodeId, nodeId)
	newNodeId[0] = newNodeId[0] + 1
	p, err := NewProver(cfg, opts.DataDir, newNodeId, commitmentAtxId)
	r.NoError(err)
	_, _, err = p.GenerateProof(ch)
	var errConfigMismatch initialization.ConfigMismatchError
	r.ErrorAs(err, &errConfigMismatch)
	r.Equal("NodeId", errConfigMismatch.Param)

	// Attempt to generate proof with different `atxId`.
	newAtxId := make([]byte, 32)
	copy(newAtxId, commitmentAtxId)
	newAtxId[0] = newAtxId[0] + 1
	p, err = NewProver(cfg, opts.DataDir, nodeId, newAtxId)
	r.NoError(err)
	_, _, err = p.GenerateProof(ch)
	r.ErrorAs(err, &errConfigMismatch)
	r.Equal("CommitmentAtxId", errConfigMismatch.Param)

	// Attempt to generate proof with different `BitsPerLabel`.
	newCfg := cfg
	newCfg.BitsPerLabel++
	p, err = NewProver(newCfg, opts.DataDir, nodeId, commitmentAtxId)
	r.NoError(err)
	_, _, err = p.GenerateProof(ch)
	r.ErrorAs(err, &errConfigMismatch)
	r.Equal("BitsPerLabel", errConfigMismatch.Param)

	// Attempt to generate proof with different `LabelsPerUnint`.
	newCfg = cfg
	newCfg.LabelsPerUnit++
	p, err = NewProver(newCfg, opts.DataDir, nodeId, commitmentAtxId)
	r.NoError(err)
	_, _, err = p.GenerateProof(ch)
	r.ErrorAs(err, &errConfigMismatch)
	r.Equal("LabelsPerUnit", errConfigMismatch.Param)
}

func TestCalcProvingDifficulty(t *testing.T) {
	t.Skip("poc")

	// Implementation of:
	// SUCCESS = msb64(HASH_OUTPUT) <= MAX_TARGET * (K1/NumLabels)

	NumLabels := uint64(4294967296)
	K1 := uint64(2000000)

	t.Logf("NumLabels: %v\n", NumLabels)
	t.Logf("K1: %v\n", K1)

	maxTarget := uint64(math.MaxUint64)
	t.Logf("\nmax target: %d\n", maxTarget)

	if ok := shared.Uint64MulOverflow(NumLabels, K1); ok {
		panic("NumLabels*K1 overflow")
	}

	x := maxTarget / NumLabels
	y := maxTarget % NumLabels
	difficulty := x*K1 + (y*K1)/NumLabels
	t.Logf("difficulty: %v\n", difficulty)

	t.Log("\ncalculating various values...\n")
	for i := 129540; i < 129545; i++ { // value 129544 pass
		// Generate a preimage.
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(i))
		t.Logf("%v: preimage: 0x%x\n", i, b)

		// Derive the hash output.
		hash := sha256.Sum256(b[:])
		t.Logf("%v: hash: Ox%x\n", i, hash)

		// Convert the hash output leading 64 bits to an integer
		// so that it could be used to perform math comparisons.
		hashNum := binary.BigEndian.Uint64(hash[:])
		t.Logf("%v: hashNum: %v\n", i, hashNum)

		// Test the difficulty requirement.
		if hashNum > difficulty {
			t.Logf("%v: Not passed. hashNum > difficulty\n", i)
		} else {
			t.Logf("%v: Great success! hashNum <= difficulty\n", i)
			break
		}

		t.Log("\n")
	}
}

type noopReporter struct{}

func (r *noopReporter) Report(context.Context, uint64) bool { return false }

type worker func(ctx context.Context, data <-chan *batch, reporter IndexReporter, labelSize uint8, ch Challenge, nonce uint32, difficulty uint64)

func benchmarkHashing(b *testing.B, size int, labelSizeBits int, workers int, work worker) {
	labelSize := labelSizeBits / 8
	challenge := make([]byte, 32, 32)
	difficulty := shared.ProvingDifficulty(uint64(size/labelSize), uint64(2000))

	var buf = make([]byte, size)
	_, err := rand.Read(buf)
	require.NoError(b, err)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewBuffer(buf)
		queue := make(chan *batch, workers)

		var producer errgroup.Group
		producer.Go(func() error {
			return produce(context.Background(), reader, []chan *batch{queue})
		})
		var eg errgroup.Group
		for workerId := 0; workerId < workers; workerId++ {
			eg.Go(func() error {
				work(context.Background(), queue, &noopReporter{}, uint8(labelSize), challenge, 0, difficulty)
				return nil
			})
		}
		producer.Wait()
		eg.Wait()
	}
}

func BenchmarkHashingLabels(b *testing.B) {

	tests := []struct {
		name      string
		f         func(*testing.B, int, int, int, worker)
		work      worker
		size      int
		labelSize int
		workers   int
	}{
		{"SHA256", benchmarkHashing, workSha256, 128 * 1024 * 1024, 8, 1},
		{"SHA256", benchmarkHashing, workSha256, 128 * 1024 * 1024, 16, 1},

		{"AES CTR", benchmarkHashing, workAESCTR, 128 * 1024 * 1024, 8, 1},
		{"AES CTR", benchmarkHashing, workAESCTR, 128 * 1024 * 1024, 16, 1},
		{"AES CTR", benchmarkHashing, workAESCTR, 128 * 1024 * 1024, 8, 2},
		{"AES CTR", benchmarkHashing, workAESCTR, 128 * 1024 * 1024, 8, 4},
		{"AES CTR", benchmarkHashing, workAESCTR, 128 * 1024 * 1024, 8, 6},
		{"AES CTR", benchmarkHashing, workAESCTR, 128 * 1024 * 1024, 8, 14},
		{"AES CTR", benchmarkHashing, workAESCTR, 128 * 1024 * 1024, 8, 20},
		{"AES CTR", benchmarkHashing, workAESCTR, 128 * 1024 * 1024, 32, 1},
		{"AES CTR", benchmarkHashing, workAESCTR, 128 * 1024 * 1024, 64, 1},
		{"AES CTR", benchmarkHashing, workAESCTR, 128 * 1024 * 1024, 128, 1},
	}

	for _, test := range tests {
		b.Run(
			fmt.Sprintf("%s|data-size:%.2fMB|label:%db|workers:%d", test.name, float64(test.size)/1024/1024, test.labelSize, test.workers),
			func(b *testing.B) { test.f(b, test.size, test.labelSize, test.workers, test.work) })
	}
}

func TestAesCtrUsedCorrectly(t *testing.T) {
	ch := []byte("hello world, challenge me!!!!!!!")
	nonce := uint32(7)
	key := append([]byte{}, ch...)
	binary.LittleEndian.AppendUint32(key, nonce)
	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	var iv [aes.BlockSize]byte
	var out [aes.BlockSize]byte
	var in [aes.BlockSize]byte

	binary.BigEndian.PutUint64(iv[8:], uint64(0))
	ctr := cipher.NewCTR(c, iv[:])
	ctr.XORKeyStream(out[:], in[:])
	ctr.XORKeyStream(out[:], in[:])

	var out2 [aes.BlockSize]byte
	binary.BigEndian.PutUint64(iv[8:], uint64(1))
	ctr = cipher.NewCTR(c, iv[:])
	ctr.XORKeyStream(out2[:], in[:])

	require.Equal(t, out, out2)
}
