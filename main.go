package main

import (
    "flag"
    log "github.com/sirupsen/logrus"
    "math/rand"
    "os"
    "sync"
    "time"
)

type AppCfg struct {
    // the url for viewers
    viewer_url *string
    // when the server turns inactive, the scale client can choose to wait the server side
    // to go back active, or simply quit the connection
    wait_on_inactive bool
    // the number of coroutines that are in connecting stage
    // if it is zero, no limit
    max_concurrent_connecting uint64
    // connecting rate limit data
    rate_limit_connecting *chan struct{}
}

func main() {
    logLevelTable := map[string]log.Level{
        "panic": log.PanicLevel,
        "error": log.ErrorLevel,
        "warn":  log.WarnLevel,
        "info":  log.InfoLevel,
        "debug": log.DebugLevel,
    }

    var cfg AppCfg
    num := flag.Int("n", 1, "Number of connections")
    logLevel := flag.String("l", "info", "Specify log level, available levels are: panic, error, warn, info and debug")
    logfile := flag.String("f", "", "Log file path, log output goes to log file instead of console")
    cfg.wait_on_inactive = *flag.Bool("e", false, "A boolean flag, if set, the program will wait when server turns inactive, otherwise just exit")
    cfg.max_concurrent_connecting = *flag.Uint64("r", 0, "Specify the maximum number of connecting attempts, no limit if set to 0")
    cfg.viewer_url = flag.String("u", "", "URL to access")

    flag.Parse()
    if level, ok := logLevelTable[*logLevel]; ok {
        log.SetLevel(level)
    } else {
        log.Fatal("Unrecognized log level, exit")
    }

    if *cfg.viewer_url == "" {
        log.Fatal("URL is not specified, exit")
    }

    if *num <= 0 {
        log.Fatal("Specify a positive number for connections!")
    }

    if *logfile != "" {
        f, err := os.OpenFile(*logfile, os.O_RDWR|os.O_CREATE, 0666)
        if err != nil {
            log.Fatal("Failed to open log file, exit")
        }
        log.SetOutput(f)
    }

    if cfg.max_concurrent_connecting > 0 {
        // note: it's buffered channel, with fixed length "max_concurrent_connecting"
        c := make(chan struct{}, cfg.max_concurrent_connecting)
        cfg.rate_limit_connecting = &c
        for i := 0; i < int(cfg.max_concurrent_connecting); i++ {
            *cfg.rate_limit_connecting <- struct{}{}
        }
    }

    // we'll need to call rand soon, let's do seed here
    rand.Seed(time.Now().UnixNano())

    wg := new(sync.WaitGroup)
    wg.Add(*num)

    for i := 0; i < *num; i++ {
        go connect(wg, i, &cfg)
    }

    wg.Wait()
    log.Info("Scale client exit")
}
