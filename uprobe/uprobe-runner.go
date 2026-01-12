package main

import (
    "fmt"
    "log"
    "os"
    "os/signal"
    "strconv"
    "strings"
    "syscall"
    "errors"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
)

//go:generate bpf2go -tags linux -target amd64 bpf uprobe.bpf.c -- -I/usr/include/x86_64-linux-gnu

func main() {
    if len(os.Args) != 3 {
        fmt.Printf("Usage: %s <binary_path> <offset>\n", os.Args[0])
        os.Exit(1)
    }

    stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

    binary := os.Args[1]
    offStr := os.Args[2]

    // Parse offset (hex or decimal)
    var offset uint64
    var err error
    if strings.HasPrefix(offStr, "0x") {
        offset, err = strconv.ParseUint(offStr[2:], 16, 64)
    } else {
        offset, err = strconv.ParseUint(offStr, 10, 64)
    }
    if err != nil || offset == 0 {
        log.Fatalf("invalid offset: %v", err)
    }

    // Load BPF object
    objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()


    // Attach uprobe
    ex, err := link.OpenExecutable(binary)
    if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

    up, err := ex.Uprobe("", objs.HandleUprobe,
        &link.UprobeOptions{
            Address:  offset,
        },
    )
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up.Close()

    fmt.Printf("Attached uprobe to %s at offset 0x%x\n", binary, offset)

    // Perf reader
    events := objs.Events
    rd, err := perf.NewReader(events, os.Getpagesize())
    if err != nil {
        log.Fatalf("failed to open perf reader: %v", err)
    }
    defer rd.Close()

    fmt.Println("Waiting for events… Ctrl-C to exit.")

    go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

    for {
        record, err := rd.Read()
        if err != nil {
            if errors.Is(err, perf.ErrClosed) {
				return
			}
            continue
        }
        fmt.Print(string(record.RawSample))
    }
}
