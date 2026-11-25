package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

var errUsage = errors.New("invalid command usage")

const usage = `Usage:
  labelreef serve -config FILE
  labelreef check -config FILE
  labelreef ctl -address IP:PORT status|reload
  labelreef ctl -address IP:PORT edit|publish FILE
  labelreef ctl -address IP:PORT sync ORIGIN
  labelreef ctl -address IP:PORT export ORIGIN
  labelreef query -address IP:PORT [options] NAME TYPE
  labelreef xfr -address IP:PORT [-base FILE] [-trace FILE] ORIGIN
  labelreef replay [-base FILE] TRACE
  labelreef inspect FILE
  labelreef rewrite FILE
  labelreef compare LEFT RIGHT
  labelreef state FILE
`

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, errUsage) {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, stderr io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "help", "-h", "--help":
		_, err := fmt.Fprint(out, usage)
		return err
	case "serve", "check":
		return configCommand(ctx, args[0], args[1:], out, stderr)
	case "ctl":
		return controlCommand(ctx, args[1:], out, stderr)
	case "query":
		return queryCommand(ctx, args[1:], out, stderr)
	case "xfr":
		return xfrCommand(ctx, args[1:], out, stderr)
	case "replay":
		return replayCommand(args[1:], out, stderr)
	case "inspect", "rewrite":
		return zoneCommand(args[0], args[1:], out)
	case "compare":
		return compareZones(args[1:], out)
	case "state":
		return showState(args[1:], out)
	default:
		return fmt.Errorf("%w: unknown command %q", errUsage, args[0])
	}
}
