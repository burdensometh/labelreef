package serve

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"labelreef/reload"
	"labelreef/serial"
	"labelreef/zone"
)

const (
	ControlHeader = "X-Labelreef-Control"
	ControlValue  = "1"
)

type Control struct {
	Manager *reload.Manager
	DNS     *Server
	Client  reload.Fetcher
}

type StatusResponse struct {
	reload.Status
	DNS       Stats        `json:"dns"`
	Transfers TransferView `json:"transfers"`
}

func (c Control) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	address := c.Manager.Runtime().Control
	if !localControl(r, address) {
		writeControlError(w, http.StatusForbidden, "expected loopback control request")
		return
	}
	var result any
	var err error
	switch r.URL.Path {
	case "/v1/status":
		if !method(w, r, http.MethodGet) {
			return
		}
		result = StatusResponse{
			Status: c.Manager.Status(), DNS: c.DNS.Stats(), Transfers: c.DNS.TransferStatus(),
		}
	case "/v1/export":
		if !method(w, r, http.MethodGet) {
			return
		}
		origin, parseErr := onlyOrigin(r.URL.RawQuery)
		if parseErr != nil {
			writeControlError(w, http.StatusBadRequest, parseErr.Error())
			return
		}
		var z *zone.ZoneVersion
		z, err = c.Manager.Export(origin)
		if err == nil {
			result = z.V1()
		}
	case "/v1/reload":
		if !method(w, r, http.MethodPost) {
			return
		}
		result, err = c.Manager.Reload()
	case "/v1/edit":
		if !body(w, r) {
			return
		}
		var edit serial.EditV1
		edit, err = serial.DecodeEdit(r.Body)
		if err == nil {
			result, err = c.Manager.Edit(edit)
		}
	case "/v1/publish":
		if !body(w, r) {
			return
		}
		var z *zone.ZoneVersion
		z, err = zone.DecodeV1(r.Body)
		if err == nil {
			result, err = c.Manager.Publish(z)
		}
	case "/v1/sync":
		if !method(w, r, http.MethodPost) {
			return
		}
		origin, parseErr := onlyOrigin(r.URL.RawQuery)
		if parseErr != nil {
			writeControlError(w, http.StatusBadRequest, parseErr.Error())
			return
		}
		if c.Client == nil {
			writeControlError(w, http.StatusServiceUnavailable, "transfer client is unavailable")
			return
		}
		result, err = c.Manager.Sync(r.Context(), origin, c.Client)
	default:
		writeControlError(w, http.StatusNotFound, "control endpoint does not exist")
		return
	}
	if err != nil {
		status := http.StatusConflict
		var limit *http.MaxBytesError
		switch {
		case errors.As(err, &limit):
			status = http.StatusRequestEntityTooLarge
		case errors.Is(err, reload.ErrUnknown):
			status = http.StatusNotFound
		case r.Context().Err() != nil:
			status = http.StatusRequestTimeout
		}
		writeControlError(w, status, err.Error())
		return
	}
	json.NewEncoder(w).Encode(result)
}

func localControl(r *http.Request, address netip.AddrPort) bool {
	if r.Header.Get("Origin") != "" || r.Header.Get(ControlHeader) != ControlValue {
		return false
	}
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !remote.Addr().Unmap().IsLoopback() {
		return false
	}
	host, err := reload.Loopback(r.Host)
	return err == nil && host == address
}

func onlyOrigin(query string) (string, error) {
	values, err := url.ParseQuery(query)
	origins := values["origin"]
	if err != nil || len(values) != 1 || len(origins) != 1 || origins[0] == "" {
		return "", fmt.Errorf("expected exactly one origin")
	}
	return origins[0], nil
}

func method(w http.ResponseWriter, r *http.Request, expected string) bool {
	if r.Method == expected {
		return true
	}
	w.Header().Set("Allow", expected)
	writeControlError(w, http.StatusMethodNotAllowed, "expected "+expected)
	return false
}

func body(w http.ResponseWriter, r *http.Request) bool {
	if !method(w, r, http.MethodPost) {
		return false
	}
	typ, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(typ, "application/json") {
		writeControlError(w, http.StatusUnsupportedMediaType, "expected application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, zone.MaxV1Bytes)
	return true
}

type controlError struct {
	Error string `json:"error"`
}

func writeControlError(w http.ResponseWriter, code int, message string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(controlError{Error: message})
}

func ControlListener(address netip.AddrPort) (net.Listener, error) {
	if !address.Addr().Unmap().IsLoopback() {
		return nil, fmt.Errorf("control listener requires loopback")
	}
	return net.ListenTCP("tcp", net.TCPAddrFromAddrPort(address))
}

func (c Control) HTTPServer() *http.Server {
	timeout := c.Manager.Runtime().SyncTimeout
	return &http.Server{
		Handler: c, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: timeout,
		WriteTimeout: timeout + 5*time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192,
	}
}

// ReadControlReply limits CLI reads without retaining a partially decoded reply.
func ReadControlReply(reply *http.Response, target any) error {
	defer reply.Body.Close()
	if err := checkControlReply(reply); err != nil {
		return err
	}
	if err := zone.DecodeJSON(reply.Body, 1<<20, target); err != nil {
		return fmt.Errorf("decode control response: %w", err)
	}
	return nil
}

func ReadControlZone(reply *http.Response) (*zone.ZoneVersion, error) {
	defer reply.Body.Close()
	if err := checkControlReply(reply); err != nil {
		return nil, err
	}
	return zone.DecodeV1(reply.Body)
}

func checkControlReply(reply *http.Response) error {
	if reply.StatusCode == http.StatusOK {
		return nil
	}
	var failure controlError
	if err := zone.DecodeJSON(reply.Body, 1<<20, &failure); err != nil {
		return fmt.Errorf("control returned %s", reply.Status)
	}
	return fmt.Errorf("control returned %s: %s", reply.Status, failure.Error)
}
