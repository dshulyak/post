package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/spacemeshos/post/config"
	"github.com/spacemeshos/post/initialization"
	"github.com/spacemeshos/post/proving"
)

const (
	input      = "/home/bartosz/workspace/post/8MB"
	cpuProfile = "cpu.prof"
	memProfile = "mem.prof"
)

func main() {
	log := logger{}

	if cpuProfile != "" {
		fmt.Printf("Starting CPU profile: %s\n", cpuProfile)
		f, err := os.Create(cpuProfile)
		if err != nil {
			log.Panic("could not create CPU profile: ", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Panic("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
		defer func() { _ = f.Close() }()
	}

	// numUnits := uint32(5242880)
	numUnits := uint32(2000)

	nodeId := make([]byte, 32)
	commitmentAtxId := make([]byte, 32)
	ch := make(proving.Challenge, 32)
	cfg := config.DefaultConfig()
	cfg.LabelsPerUnit = 1 << 12
	cfg.MaxNumUnits = 5242880

	opts := config.DefaultInitOpts()
	opts.ComputeProviderID = int(initialization.CPUProviderID())
	opts.NumUnits = numUnits
	opts.DataDir = input
	// opts.MaxFileSize = 21474836480

	init, err := initialization.NewInitializer(
		initialization.WithNodeId(nodeId),
		initialization.WithCommitmentAtxId(commitmentAtxId),
		initialization.WithConfig(cfg),
		initialization.WithInitOpts(opts),
		initialization.WithLogger(log),
	)
	if err != nil {
		log.Panic("failed creating initialized: %v", err)
	}

	_ = init.Initialize(context.Background())

	p, err := proving.NewProver(cfg, opts.DataDir, nodeId, commitmentAtxId)
	p.SetLogger(log)

	binary.BigEndian.PutUint64(ch, uint64(opts.NumUnits))
	ch[7] = 128 // 96s

	_, _, err = p.GenerateProof(ch)

	pprof.StopCPUProfile()
	if err != nil {
		panic(fmt.Sprintf("failed to generate proof: %v", err))
	}

	if memProfile != "" {
		fmt.Printf("Collecting memory profile to %s\n", memProfile)
		f, err := os.Create(memProfile)
		if err != nil {
			log.Panic("could not create memory profile: ", err)
		}
		defer func() { _ = f.Close() }()
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Panic("could not write memory profile: ", err)
		}
	}

}

type logger struct{}

func (l logger) Info(msg string, args ...any)    { log.Printf("\tINFO\t"+msg, args...) }
func (l logger) Debug(msg string, args ...any)   { log.Printf("\tDEBUG\t"+msg, args...) }
func (l logger) Warning(msg string, args ...any) { log.Printf("\tWARN\t"+msg, args...) }
func (l logger) Error(msg string, args ...any)   { log.Printf("\tERROR\t"+msg, args...) }
func (l logger) Panic(msg string, args ...any)   { log.Fatalf(msg, args...) }
