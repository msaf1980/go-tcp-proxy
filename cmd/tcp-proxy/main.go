package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"

	proxy "github.com/msaf1980/go-tcp-proxy"
)

var (
	version = "0.0.0-src"
	matchid = uint64(0)
	connid  = uint64(0)
	logger  proxy.ColorLogger

	localAddr   = flag.String("l", ":9999", "local address")
	remoteAddr  = flag.String("r", "localhost:80", "remote address")
	verbose     = flag.Bool("v", false, "display server actions")
	veryverbose = flag.Bool("vv", false, "display server actions and all tcp data")
	nagles      = flag.Bool("n", false, "disable nagles algorithm")
	hex         = flag.Bool("h", false, "output hex")
	colors      = flag.Bool("color", false, "output ansi colors")
	unwrapTLS   = flag.Bool("unwrap-tls", false, "remote connection with TLS exposed unencrypted locally")
	match       = flag.String("match", "", "match regex (in the form 'regex')")
	replace     = flag.String("replace", "", "replace regex (in the form 'regex~replacer')")

	timeoutMin  = flag.Int("tmin", 0, "minimal injected timeout for proxying request (ms)")
	timeoutMax  = flag.Int("tmax", 0, "maximum injected timeout for proxying request (ms)")
	timeoutSize = flag.Int("tsize", 0, "responce size in bytes, when timeout injected")

	conTimeoutMin = flag.Int("ctmin", 0, "minimal injected connection timeout (ms)")
	conTimeoutMax = flag.Int("ctmax", 0, "maximum injected connection timeout (ms)")

	conTimeoutEnable = flag.Bool("-c", true, "enable connection timeout by default (can be changed in runtime with SIGUSR1")
)

func sigHandler() {
	var quit bool

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)

	// foreach signal received
	for signal := range sig {
		//      logEvent(lognotice, sys, "Signal received: "+signal.String())

		switch signal {
		case syscall.SIGINT, syscall.SIGTERM:
			quit = true
		case syscall.SIGHUP, syscall.SIGUSR1:
			if atomic.LoadInt32(&proxy.ConTimeoutEnable) > 0 {
				atomic.StoreInt32(&proxy.ConTimeoutEnable, 0)
				logger.Info("go-tcp-proxy disable connection timeout")
			} else {
				atomic.StoreInt32(&proxy.ConTimeoutEnable, 1)
				logger.Info("go-tcp-proxy enable connection timeout")
			}
			quit = false
		}

		if quit {
			os.Exit(0)
		}
	}
}

func main() {
	flag.Parse()

	logger := proxy.ColorLogger{
		Verbose: *verbose,
		Color:   *colors,
	}

	logger.Info("go-tcp-proxy (%s) proxing from %v to %v ", version, *localAddr, *remoteAddr)

	laddr, err := net.ResolveTCPAddr("tcp", *localAddr)
	if err != nil {
		logger.Warn("Failed to resolve local address: %s", err)
		os.Exit(1)
	}
	raddr, err := net.ResolveTCPAddr("tcp", *remoteAddr)
	if err != nil {
		logger.Warn("Failed to resolve remote address: %s", err)
		os.Exit(1)
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		logger.Warn("Failed to open local port to listen: %s", err)
		os.Exit(1)
	}

	matcher := createMatcher(*match)
	replacer := createReplacer(*replace)

	if *veryverbose {
		*verbose = true
	}

	conTimeoutRand := proxy.NewIntRange(*conTimeoutMin, *conTimeoutMin)
	timeoutRand := proxy.NewIntRange(*timeoutMin, *timeoutMin)
	if !*conTimeoutEnable {
		proxy.ConTimeoutEnable = 0
	}

	// start the signal monitoring routine
	go sigHandler()

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			logger.Warn("Failed to accept connection '%s'", err)
			continue
		}
		connid++

		var p *proxy.Proxy
		if *unwrapTLS {
			logger.Info("Unwrapping TLS")
			p = proxy.NewTLSUnwrapped(conn, laddr, raddr, *remoteAddr)
		} else {
			p = proxy.New(conn, laddr, raddr)
		}

		p.Matcher = matcher
		p.Replacer = replacer

		p.Timeout = timeoutRand
		p.TimeoutSize = *timeoutSize

		p.ConTimeout = conTimeoutRand

		p.Nagles = *nagles
		p.OutputHex = *hex
		p.Log = proxy.ColorLogger{
			Verbose:     *verbose,
			VeryVerbose: *veryverbose,
			Prefix:      fmt.Sprintf("Connection #%03d ", connid),
			Color:       *colors,
		}

		go p.Start()
	}
}

func createMatcher(match string) func([]byte) {
	if match == "" {
		return nil
	}
	re, err := regexp.Compile(match)
	if err != nil {
		logger.Warn("Invalid match regex: %s", err)
		return nil
	}

	logger.Info("Matching %s", re.String())
	return func(input []byte) {
		ms := re.FindAll(input, -1)
		for _, m := range ms {
			matchid++
			logger.Info("Match #%d: %s", matchid, string(m))
		}
	}
}

func createReplacer(replace string) func([]byte) []byte {
	if replace == "" {
		return nil
	}
	//split by / (TODO: allow slash escapes)
	parts := strings.Split(replace, "~")
	if len(parts) != 2 {
		logger.Warn("Invalid replace option")
		return nil
	}

	re, err := regexp.Compile(string(parts[0]))
	if err != nil {
		logger.Warn("Invalid replace regex: %s", err)
		return nil
	}

	repl := []byte(parts[1])

	logger.Info("Replacing %s with %s", re.String(), repl)
	return func(input []byte) []byte {
		return re.ReplaceAll(input, repl)
	}
}
