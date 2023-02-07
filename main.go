package main

import (
    "bytes"
    "flag"
    "math/rand"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"

    log "github.com/sirupsen/logrus"
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
    // stats path
    stats_dst *string
}

type send_stats_func func([]byte, string)

var stat_file *os.File

var stats_report_interval int64

func send_stats_disk(b []byte, target string) {
    if stat_file == nil {
        var err error
        stat_file, err = os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
        if err != nil {
            panic(err)
        }
    }

    stat_file.Write(b)
}

func send_stats_post(b []byte, target string) {
    req, err := http.NewRequest("POST", target, bytes.NewBuffer(b))
    req.Header.Set("Content-Type", "application/json")
    if err != nil {
        panic(err)
    }

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    resp.Body.Close()
}

// by default, it will just write the file
var send_stats send_stats_func = send_stats_disk

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
    wait_on_inactive := flag.Bool("e", false, "A boolean flag, if set, the program will wait when server turns inactive, otherwise just exit")
    max_connecting := flag.Uint64("r", 0, "Specify the maximum number of connecting attempts, no limit if set to 0")
    _stats_report_inteval := flag.Int64("i", 10, "The stats report interval")
    cfg.viewer_url = flag.String("u", "", "URL to access")
    cfg.stats_dst = flag.String("t", "", "Specify where the stats data should be sent. It can be local file or remote POST address(starts with http:// or https://)")

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
        f, err := os.OpenFile(*logfile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
        if err != nil {
            log.Fatal("Failed to open log file, exit")
        }
        log.SetOutput(f)
    }

    if *cfg.stats_dst == "" {
        cur := time.Now()
        *cfg.stats_dst = cur.Format("2006-01-05_15:04:05.stats.txt")
    } else if strings.HasPrefix(*cfg.stats_dst, "http://") || strings.HasPrefix(*cfg.stats_dst, "https://") {
        send_stats = send_stats_post
    }

    if *_stats_report_inteval < 0 {
        stats_report_interval = 10
    } else {
        stats_report_interval = *_stats_report_inteval
    }
    cfg.wait_on_inactive = *wait_on_inactive

    if *max_connecting > 0 {
        cfg.max_concurrent_connecting = *max_connecting
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
