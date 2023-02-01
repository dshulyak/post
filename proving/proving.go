package proving

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/spacemeshos/sha256-simd"
	"golang.org/x/sync/errgroup"

	"github.com/spacemeshos/post/config"
	"github.com/spacemeshos/post/initialization"
	"github.com/spacemeshos/post/oracle"
	"github.com/spacemeshos/post/persistence"
	"github.com/spacemeshos/post/shared"
)

const (
	NumWorkersPerNonce    = 4
	NumNoncesPerIteration = 5   // TODO(moshababo): update the recommended value
	MaxNumIterations      = 100 // TODO(moshababo): update the recommended value
)

type (
	Config              = config.Config
	Proof               = shared.Proof
	ProofMetadata       = shared.ProofMetadata
	Logger              = shared.Logger
	Challenge           = shared.Challenge
	ConfigMismatchError = shared.ConfigMismatchError

	Metadata  = shared.PostMetadata
	DiskState = initialization.DiskState
)

var (
	FastOracle = oracle.FastOracle
	UInt64LE   = shared.UInt64LE
)

type Prover struct {
	nodeId          []byte
	commitmentAtxId []byte

	cfg     Config
	datadir string

	diskState *DiskState

	logger Logger
}

func NewProver(cfg Config, datadir string, nodeId, commitmentAtxId []byte) (*Prover, error) {
	return &Prover{
		cfg:             cfg,
		datadir:         datadir,
		nodeId:          nodeId,
		commitmentAtxId: commitmentAtxId,
		diskState:       initialization.NewDiskState(datadir, uint(cfg.BitsPerLabel)),
		logger:          shared.DisabledLogger{},
	}, nil
}

// GenerateProof (analogous to the PoST protocol Execution phase) receives a challenge that cannot be predicted,
// and reads the entire PoST data to generate a proof in response to the challenge to prove that the prover data exists at the time of invocation.
// Generating a proof can be repeated arbitrarily many times without repeating the PoST protocol Initialization phase;
// thus despite the initialization essentially serving as a PoW, the amortized computational complexity can be made arbitrarily small.
func (p *Prover) GenerateProof(challenge Challenge) (*Proof, *ProofMetadata, error) {
	m, err := p.loadMetadata()
	if err != nil {
		return nil, nil, err
	}

	if err := p.verifyGenerateProofAllowed(m); err != nil {
		return nil, nil, err
	}

	numLabels := uint64(m.NumUnits) * p.cfg.LabelsPerUnit

	for i := 0; i < MaxNumIterations; i++ {
		startNonce := uint32(i) * NumNoncesPerIteration
		endNonce := startNonce + NumNoncesPerIteration - 1

		p.logger.Debug("proving: starting iteration %d; startNonce: %v, endNonce: %v, challenge: %x", i+1, startNonce, endNonce, challenge)

		solutionNonceResult, err := p.tryManyNonces(context.Background(), numLabels, challenge, startNonce, endNonce)
		// solutionNonceResult, err := p.tryNonces(numLabels, challenge, startNonce, endNonce)
		if err != nil {
			return nil, nil, err
		}

		if solutionNonceResult != nil {
			p.logger.Info("proving: generated proof after %d iteration(s). nonce: %d", i+1, solutionNonceResult.nonce)

			proof := &Proof{
				Nonce:   solutionNonceResult.nonce,
				Indices: solutionNonceResult.indices,
			}
			proofMetadata := &ProofMetadata{
				NodeId:          p.nodeId,
				CommitmentAtxId: p.commitmentAtxId,
				Challenge:       challenge,
				BitsPerLabel:    p.cfg.BitsPerLabel,
				LabelsPerUnit:   p.cfg.LabelsPerUnit,
				NumUnits:        m.NumUnits,
				K1:              p.cfg.K1,
				K2:              p.cfg.K2,
			}
			return proof, proofMetadata, nil
		}
	}

	return nil, nil, fmt.Errorf("failed to generate proof; tried %v iterations, %v nonces each", MaxNumIterations, NumNoncesPerIteration)
}

func (p *Prover) SetLogger(logger Logger) {
	p.logger = logger
}

func (p *Prover) verifyGenerateProofAllowed(m *Metadata) error {
	if err := p.verifyMetadata(m); err != nil {
		return err
	}

	if err := p.verifyInitCompleted(uint(m.NumUnits)); err != nil {
		return err
	}

	return nil
}

func (p *Prover) verifyInitCompleted(numUnits uint) error {
	ok, err := p.initCompleted(numUnits)
	if err != nil {
		return err
	}
	if !ok {
		return shared.ErrInitNotCompleted
	}

	return nil
}

func (p *Prover) initCompleted(numUnits uint) (bool, error) {
	numLabelsWritten, err := p.diskState.NumLabelsWritten()
	if err != nil {
		return false, err
	}

	target := uint64(numUnits) * uint64(p.cfg.LabelsPerUnit)
	return numLabelsWritten == target, nil
}

func (p *Prover) loadMetadata() (*Metadata, error) {
	return initialization.LoadMetadata(p.datadir)
}

func (p *Prover) verifyMetadata(m *Metadata) error {
	if !bytes.Equal(p.nodeId, m.NodeId) {
		return ConfigMismatchError{
			Param:    "NodeId",
			Expected: fmt.Sprintf("%x", p.nodeId),
			Found:    fmt.Sprintf("%x", m.NodeId),
			DataDir:  p.datadir,
		}
	}

	if !bytes.Equal(p.commitmentAtxId, m.CommitmentAtxId) {
		return ConfigMismatchError{
			Param:    "CommitmentAtxId",
			Expected: fmt.Sprintf("%x", p.commitmentAtxId),
			Found:    fmt.Sprintf("%x", m.CommitmentAtxId),
			DataDir:  p.datadir,
		}
	}

	if p.cfg.BitsPerLabel != m.BitsPerLabel {
		return ConfigMismatchError{
			Param:    "BitsPerLabel",
			Expected: fmt.Sprintf("%d", p.cfg.BitsPerLabel),
			Found:    fmt.Sprintf("%d", m.BitsPerLabel),
			DataDir:  p.datadir,
		}
	}

	if p.cfg.LabelsPerUnit != m.LabelsPerUnit {
		return ConfigMismatchError{
			Param:    "LabelsPerUnit",
			Expected: fmt.Sprintf("%d", p.cfg.LabelsPerUnit),
			Found:    fmt.Sprintf("%d", m.LabelsPerUnit),
			DataDir:  p.datadir,
		}
	}

	return nil
}

func (p *Prover) tryNonce(ctx context.Context, numLabels uint64, ch Challenge, nonce uint32, readerChan <-chan []byte, difficulty uint64) ([]byte, error) {
	bitsPerIndex := uint(shared.BinaryRepresentationMinBits(numLabels))
	buf := bytes.NewBuffer(make([]byte, shared.Size(bitsPerIndex, uint(p.cfg.K2)))[0:0])
	gsWriter := shared.NewGranSpecificWriter(buf, bitsPerIndex)
	var index uint64
	var passed uint
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: tried: %v, passed: %v, needed: %v", ctx.Err(), index, passed, p.cfg.K2)
		case label, more := <-readerChan:
			if !more {
				return nil, fmt.Errorf("exhausted all labels; tried: %v, passed: %v, needed: %v", index, passed, p.cfg.K2)
			}

			hash := FastOracle(ch, nonce, label)

			// Convert the fast oracle output's leading 64 bits to a number,
			// so that it could be used to perform math comparisons.
			hashNum := UInt64LE(hash[:])

			// Check the difficulty requirement.
			if hashNum <= difficulty {
				if err := gsWriter.WriteUintBE(index); err != nil {
					return nil, err
				}
				passed++

				if passed >= uint(p.cfg.K2) {
					if err := gsWriter.Flush(); err != nil {
						return nil, err
					}
					return buf.Bytes(), nil
				}
			}

			index++
		}
	}
}

type nonceResult struct {
	nonce   uint32
	indices []byte
	err     error
}

type batch struct {
	data    []byte
	index   uint64
	release func()
}

func (p *Prover) tryManyNonces(ctx context.Context, numLabels uint64, challenge Challenge, start, end uint32) (*nonceResult, error) {
	var eg errgroup.Group

	nonceWorkers := NumWorkersPerNonce
	workers := end - start + 1

	var workerQeues []chan batch
	for i := 0; i < int(workers); i++ {
		workerQeues = append(workerQeues, make(chan batch, nonceWorkers*1))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	eg.Go(func() error {
		reader, err := persistence.NewLabelsReader(p.datadir, uint(p.cfg.BitsPerLabel))
		if err != nil {
			return err
		}
		defer reader.Close()
		return produce(ctx, reader, workerQeues)
	})

	results := make(chan *nonceResult, end-start+1)
	for i := uint32(0); i < workers; i++ {
		queue := workerQeues[i]
		nonce := i + start
		eg.Go(func() error {
			res, err := p.trySingleNonce(ctx, numLabels, challenge, nonce, queue, nonceWorkers)
			if err != nil {
				p.logger.Info("failed to try nonce %d: %v", nonce, err)
			} else if res != nil {
				p.logger.Info("Generated proof with nonce %d", nonce)
				cancel() // we have a proof - stop other workers
				results <- res
			}
			return nil
		})
	}

	eg.Wait()
	close(results)
	for res := range results {
		return res, nil
	}
	return nil, ctx.Err()
}

func produce(ctx context.Context, reader io.Reader, workerQeues []chan batch) error {
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

		buffer := bufferPool.Get().([]byte)
		n, err := reader.Read(buffer)
		if err != nil {
			return nil
		}
		for i := 0; i < len(workerQeues); i++ {
			workerQeues[i] <- batch{
				data:    buffer,
				index:   index,
				release: func() { bufferPool.Put(buffer) },
			}
		}
		index += uint64(n)
	}
}

type IndexReporter interface {
	Report(context.Context, uint64)
}

type IndexConsumer struct {
	Indexes chan uint64
}

func (c *IndexConsumer) Report(ctx context.Context, index uint64) {
	select {
	case c.Indexes <- index:
	case <-ctx.Done():
	}
}

func work(ctx context.Context, data <-chan batch, reporter IndexReporter, labelSize uint8, ch Challenge, nonce uint32, difficulty uint64) (tried uint64) {
	hasher := sha256.New().(*sha256.Digest)
	hasher.Write(ch)
	var nb [4]byte
	binary.LittleEndian.PutUint32(nb[:], nonce)
	hasher.Write(nb[:])
	var hb [32]byte
	for batch := range data {
		index := batch.index
		labels := batch.data
		for {
			if len(labels) == 0 {
				break
			}
			tried += 1
			label := labels[:labelSize]
			labels = labels[labelSize:]

			s := *hasher
			s.Write(label)
			s.CheckSumInto(&hb)
			// hasher.Sum(hb[:0])

			value := uint64(hb[0]) | uint64(hb[1])<<8 | uint64(hb[2])<<16 | uint64(hb[3])<<24 |
				uint64(hb[4])<<32 | uint64(hb[5])<<40 | uint64(hb[6])<<48 | uint64(hb[7])<<56

			if value <= difficulty {
				reporter.Report(ctx, index)
			}
			index++
		}
		batch.release()
	}
	return tried
}

func (p *Prover) trySingleNonce(ctx context.Context, numLabels uint64, challenge Challenge, nonce uint32, data chan batch, workers int) (*nonceResult, error) {
	p.logger.Info("Trying nonce %d", nonce)
	difficulty := shared.ProvingDifficulty(numLabels, uint64(p.cfg.K1))

	var eg errgroup.Group

	indexConsumer := &IndexConsumer{
		Indexes: make(chan uint64, workers*10),
	}

	var tried atomic.Uint64
	for workerId := 0; workerId < workers; workerId++ {
		eg.Go(func() error {
			t := work(ctx, data, indexConsumer, p.cfg.BitsPerLabel/8, challenge, nonce, difficulty)
			tried.Add(t)
			return nil
		})
	}

	done := make(chan struct{})
	go func() {
		eg.Wait()
		close(done)
	}()

	var passed []uint64

	for {
		select {
		case <-done:
			return nil, fmt.Errorf("exhausted all labels; tried: %v, passed: %v, needed: %v", tried.Load(), len(passed), p.cfg.K2)
		case index := <-indexConsumer.Indexes:
			passed = append(passed, index)
			if len(passed) >= int(p.cfg.K2) {
				p.logger.Info("Found enough label indexes; tried: %v, passed: %v, needed: %v", tried.Load(), len(passed), p.cfg.K2)
				sort.Slice(passed, func(i, j int) bool {
					return i < j
				})

				bitsPerIndex := uint(shared.BinaryRepresentationMinBits(numLabels))
				buf := bytes.NewBuffer(make([]byte, shared.Size(bitsPerIndex, uint(p.cfg.K2)))[0:0])
				gsWriter := shared.NewGranSpecificWriter(buf, bitsPerIndex)
				for _, p := range passed {
					if err := gsWriter.WriteUintBE(p); err != nil {
						return nil, err
					}
				}

				if err := gsWriter.Flush(); err != nil {
					return nil, err
				}
				return &nonceResult{nonce, buf.Bytes(), nil}, nil
			}
		}
	}
}

func (p *Prover) tryNonces(numLabels uint64, challenge Challenge, startNonce, endNonce uint32) (*nonceResult, error) {
	difficulty := shared.ProvingDifficulty(numLabels, uint64(p.cfg.K1))

	reader, err := persistence.NewLabelsReader(p.datadir, uint(p.cfg.BitsPerLabel))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	gsReader := shared.NewGranSpecificReader(reader, uint(p.cfg.BitsPerLabel))

	numWorkers := endNonce - startNonce + 1
	workersChans := make([]chan []byte, numWorkers)
	// workersComplete channel will be closed when worker stops listening for appropriate workersChan
	workersComplete := make([]chan struct{}, numWorkers)
	for i := range workersChans {
		workersChans[i] = make(chan []byte, 1)
		workersComplete[i] = make(chan struct{})
	}
	resultsChan := make(chan *nonceResult, numWorkers)
	errChan := make(chan error, 1)

	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start IO worker.
	// Feed all labels into each worker chan.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			label, err := gsReader.ReadNext()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					errChan <- err
				}
				for i := range workersChans {
					close(workersChans[i])
				}
				return
			}

			for i := range workersChans {
				select {
				case workersChans[i] <- label:
				case <-workersComplete[i]:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Start a worker for each nonce.
	// TODO(dshulyak) it would be more efficient to start a worker per CPU and distribute work among
	// them but it is not trivial
	for i := uint32(0); i < numWorkers; i++ {
		i := i
		wg.Add(1)
		go func() {
			nonce := startNonce + i
			indices, err := p.tryNonce(ctx, numLabels, challenge, nonce, workersChans[i], difficulty)
			close(workersComplete[i])
			resultsChan <- &nonceResult{nonce, indices, err}
			wg.Done()
		}()
	}

	// return last observed error if all workers failed, otherwise return first found result
	for i := uint32(0); i < numWorkers; i++ {
		select {
		case result := <-resultsChan:
			if result.err != nil {
				p.logger.Debug("proving: nonce %v failed: %v", result.nonce, result.err)
			} else {
				p.logger.Debug("proving: nonce %v succeeded", result.nonce)
				return result, nil
			}
		case err := <-errChan:
			p.logger.Debug("proving: error: %v", err)
			return nil, err
		}
	}
	return nil, nil
}
