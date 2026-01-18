package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/grandcat/zeroconf"
)

func discoverSlaves() {
	resolver, _ := zeroconf.NewResolver(nil)
	entries := make(chan *zeroconf.ServiceEntry)

	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			// entry.AddrIPv4 contains the IP needed to connect
			fmt.Printf("Found Slave: %s at %s:%d\n", entry.Instance, entry.AddrIPv4, entry.Port)
			// Store this in a thread-safe map/slice for the Vue frontend
		}
	}(entries)

	ctx := context.Background()
	err := resolver.Browse(ctx, "_co2-monitor._tcp", "local.", entries)
	if err != nil {
		log.Fatalln("Failed to browse:", err.Error())
	}
}

func main() {

	go func() {
		for {
			discoverSlaves()
			time.Sleep(5)
		}
	}()

	fmt.Printf("hello world")
	select {}
}
