package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"labelreef/reload"
	"labelreef/serve"
	"labelreef/zone"
)

func controlCommand(ctx context.Context, args []string, out, stderr io.Writer) error {
	flags := flag.NewFlagSet("ctl", flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("address", "", "numeric loopback control IP:port")
	timeout := flags.Duration("timeout", 20*time.Second, "total request timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *timeout <= 0 || *timeout > 6*time.Minute || flags.NArg() == 0 {
		return fmt.Errorf("%w: ctl requires an action and a positive bounded timeout", errUsage)
	}
	remote, err := reload.Loopback(*address)
	if err != nil {
		return err
	}
	action, params := flags.Arg(0), flags.Args()[1:]
	verb, path, err := controlRoute(action, params)
	if err != nil {
		return err
	}
	var input io.Reader
	if action == "edit" || action == "publish" || action == "batch" {
		f, err := os.Open(params[0])
		if err != nil {
			return err
		}
		defer f.Close()
		input = f
	}
	request, err := http.NewRequestWithContext(ctx, verb, "http://"+remote.String()+path, input)
	if err != nil {
		return err
	}
	request.Header.Set(serve.ControlHeader, serve.ControlValue)
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	client := loopbackHTTPClient(*timeout)
	reply, err := client.Do(request)
	if err != nil {
		return err
	}
	if action == "export" {
		snapshot, err := serve.ReadControlZone(reply)
		if err != nil {
			return err
		}
		return zone.EncodeV1(out, snapshot)
	}
	var value any
	switch action {
	case "status":
		value = new(serve.StatusResponse)
	case "reload":
		value = new(reload.Status)
	case "batch":
		value = new(reload.BatchReceipt)
	default:
		value = new(reload.Receipt)
	}
	if err := serve.ReadControlReply(reply, value); err != nil {
		return err
	}
	return zone.EncodeJSON(out, value)
}

func controlRoute(action string, args []string) (string, string, error) {
	switch action {
	case "status":
		if len(args) == 0 {
			return http.MethodGet, "/v1/status", nil
		}
	case "reload":
		if len(args) == 0 {
			return http.MethodPost, "/v1/reload", nil
		}
	case "edit", "publish", "batch":
		if len(args) == 1 {
			return http.MethodPost, "/v1/" + action, nil
		}
	case "sync", "export":
		if len(args) == 1 {
			query := url.Values{"origin": []string{args[0]}}
			method := http.MethodPost
			if action == "export" {
				method = http.MethodGet
			}
			return method, "/v1/" + action + "?" + query.Encode(), nil
		}
	}
	return "", "", fmt.Errorf("%w: unexpected action or arguments for %q", errUsage, action)
}

func loopbackHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
