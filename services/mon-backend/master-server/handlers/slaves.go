package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/mirce-a/co2-mon-master/services/mon-backend/master-server/models"
)

type SlaveHandler struct {
	ConnectedDevices *[]models.Device
}

func (h *SlaveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if r.URL.Path == "/api/slaves/search" || r.URL.Path == "/api/slaves/search/" {
			h.searchSlaves(w, r)
			return
		}
		if r.URL.Path == "/api/slaves/readco2" || r.URL.Path == "/api/slaves/readco2/" {
			h.readCo2(w, r)
			return
		}
	}
}

func (s *SlaveHandler) readCo2(w http.ResponseWriter, r *http.Request) {
	return
}

func (s *SlaveHandler) searchSlaves(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		http.Error(w, "Failed to initialize resolver", http.StatusInternalServerError)
		return
	}

	entries := make(chan *zeroconf.ServiceEntry)
	resp := make([]models.SlaveSearchResponse, 0)

	// Use a WaitGroup or a separate goroutine to collect results
	// so we don't block the Browse call itself
	go func() {
		for entry := range entries {
			if len(entry.AddrIPv4) > 0 {
				resp = append(resp, models.SlaveSearchResponse{
					Name: entry.Instance,
					Addr: entry.AddrIPv4[0].String(),
				})
			}
		}
	}()

	// 2. Start the browse operation
	err = resolver.Browse(ctx, "_co2-monitor._tcp", "local.", entries)
	if err != nil {
		http.Error(w, "Discovery failed", http.StatusInternalServerError)
		return
	}

	// 3. Wait for the context to time out (finish searching)
	<-ctx.Done()

	// 4. Send the final accumulated list
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("JSON error: %v", err)
	}
}
