package main

import (
    "flag"
    log "github.com/sirupsen/logrus"
    "math/rand"
    "os"
    "sync"
    "time"
)

func task() {

}

func main() {
    logLevelTable := map[string]log.Level{
        "panic": log.PanicLevel,
        "error": log.ErrorLevel,
        "warn":  log.WarnLevel,
        "info":  log.InfoLevel,
        "debug": log.DebugLevel,
    }

    url := flag.String("u", "", "URL to access")
    num := flag.Int("n", 1, "Number of connections")
    logLevel := flag.String("l", "info", "Specify log level, available levels are: panic, error, warn, info and debug")
    logfile := flag.String("f", "", "Log file path")

    flag.Parse()
    if level, ok := logLevelTable[*logLevel]; ok {
        log.SetLevel(level)
    } else {
        log.Fatal("Unrecognized log level, exit")
    }

    if *url == "" {
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

    // we'll need to call rand soon, let's do seed here
    rand.Seed(time.Now().UnixNano())

    wg := new(sync.WaitGroup)
    wg.Add(*num)

    for i := 0; i < *num; i++ {
        go connect(i, wg, *url)
    }

    wg.Wait()
    log.Info("Scale client exit")
}
