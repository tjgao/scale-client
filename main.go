package main

import (
    "bytes"
    b64 "encoding/base64"
    "encoding/binary"
    "flag"
    "fmt"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/json"
    "math/rand"
    "net/http"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"

    log "github.com/sirupsen/logrus"
)

type rtcbackup_payload struct {
    Version string     `json:"version"`
    AppId string       `json:"appId"`
    StreamId string    `json:"streamId"`
    Action string      `json:"action"`
    EnableSubAuth bool `json:"enableSubAuth"`
    Exp float64        `json:"exp"`
}


type RtcBackupCfg struct {
    // sub token id
    stoken_id uint64
    // pub token id
    ptoken_id uint64
    // sub token
    stoken *string
    // pub token
    ptoken *string
    // platform
    platform *string
    // appId
    appId string
    // appKey
    appKey string
}

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
    // stats channel
    stats_ch *chan []byte
    // flag for turn on pion dbg
    pion_dbg bool
    // test name
    test_name *string
    // remote codec
    codec *string
    // stream account id
    streamAccountId string
    // stream name
    streamName string
    // rtcbackup endpoint?
    rtcbackup bool
    // rtcbackup cfg
    rtcbackup_cfg RtcBackupCfg
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
    go func() {
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
    }()
}

// by default, it will just write the file
var send_stats send_stats_func = send_stats_disk

func notify_send_stats(st chan []byte, dst string) {
    for {
        select {
        case b := <-st:
            send_stats(b, dst)
        }
    }
}

func get_domain_suffix(viewer_url *string) string {
    domain_splits :=  strings.Split(strings.Split(*viewer_url, ".")[0], "-")
    domain := ""
    if len(domain_splits) > 1 {
        for _, s := range domain_splits[1:] {
            domain += "-"
            domain += s
        }
    }
    return domain
}


// parse the url to get stream account id and name
func parse(url *string) map[string]string {
    re := regexp.MustCompile("http.+streamId=(?P<streamAccountId>[0-9a-zA-Z_.-]+)/(?P<streamName>[0-9a-zA-Z_.-]+)")
    r := re.FindAllStringSubmatch(*url, -1)[0]
    keys := re.SubexpNames()
    md := map[string]string{}
    for i, n := range r {
        md[keys[i]] = n
    }
    return md
}

func uint64_bytes(n uint64) string {
    bs := make([]byte, 8)
    binary.BigEndian.PutUint64(bs, n)
    skipped := false
    var buf bytes.Buffer
    for _, b := range bs {
        // skip leading 0s
        if b == 0 && !skipped {
            continue
        } else {
            skipped = true
        }
        buf.WriteByte(b)
    }
    return strings.TrimRight(b64.StdEncoding.EncodeToString(buf.Bytes()), "=")
}


func generate_appid(streamId string, ptoken_id uint64, stoken_id uint64) string {
    return streamId + "." + uint64_bytes(ptoken_id) + "." + uint64_bytes(stoken_id)
}

func generate_rtcbackup_name(ptoken_id uint64, stoken_id uint64, streamName *string) string {
    return uint64_bytes(ptoken_id) + "." + uint64_bytes(stoken_id) + "." + *streamName
}

func generate_appkey(ptoken *string, stoken *string) string {
    bs := sha256.Sum256([]byte(*ptoken + *stoken))
    var buf bytes.Buffer
    for _, b := range bs {
        buf.WriteString(fmt.Sprintf("%02x", b))
    }
    return buf.String()
}

func url_friendly(b string) string {
    return strings.ReplaceAll(strings.ReplaceAll(b, "+", "-"), "/", "_")
}

func hmac_sha256(body string, secret string) string {
    h := hmac.New(sha256.New, []byte(secret))
    h.Write([]byte(body))
    bs := h.Sum(nil)
    return b64.StdEncoding.EncodeToString(bs)
}

func generate_rtcbackup_payload(appId string, streamName string) string {
    exp := float64(time.Now().UnixMilli())/1000.0 + 60
    p := rtcbackup_payload{Version: "1.0", AppId: appId, StreamId: streamName, Action: "sub", EnableSubAuth: false, Exp: exp}
    bs, err := json.Marshal(&p)
    if err != nil {
        log.Fatal("Failed to create json: ", err);
    }
    return string(bs)
}

func main() {
    if len(os.Args) < 2 {
        log.Info("Available subcommands: ws, rb. Please check the help: <program> <subcommand> -h")
        os.Exit(0)
    }

    logLevelTable := map[string]log.Level{
        "panic": log.PanicLevel,
        "error": log.ErrorLevel,
        "warn":  log.WarnLevel,
        "info":  log.InfoLevel,
        "debug": log.DebugLevel,
    }

    var (
        test_name string
        codec string
        num int
        logLevel string
        logfile string
        pion_dbg bool
        connecting_time uint64
        max_connecting uint64
        report_interval int64
        retry_times int64
        stats_dst string
        ws = flag.NewFlagSet("ws", flag.ExitOnError)
        rtcbackup = flag.NewFlagSet("rb", flag.ExitOnError)

        viewer_url string
        wait_on_inactive bool

        ptkid uint64
        stkid uint64
        ptoken string
        stoken string
        accountId string
        streamName string
        platform string
    )

    // setup common flags
    func() {
        for _, fs := range []*flag.FlagSet{ws, rtcbackup} {
            fs.StringVar(&test_name, "name", "", "Name of the test")
            fs.StringVar(&codec, "codec", "h264", "Codec used by remote side. Valid options are h264, vp8 and vp9.")
            fs.IntVar(&num, "num", 1, "Number of connections")
            fs.StringVar(&logLevel, "level", "info", "Specify log level, available levels are: panic, error, warn, info and debug.")
            fs.StringVar(&logfile, "logfile", "", "Log file path, log output goes to log file instead of console.")
            fs.BoolVar(&pion_dbg, "dbg", false, "Turn on pion debug so that more internal info will be printed out.")
            fs.Uint64Var(&connecting_time, "connecting_time", 0, "All the connections will be evenly distributed in the time (seconds) to avoid burst connections.")
            fs.Uint64Var(&max_connecting, "max_connecting", 0, "Specify the maximum number of connecting attempts, no limit if set to 0. It will disable connecting_time if set.")
            fs.Int64Var(&report_interval, "report_interval", 10, "The stats report interval.")
            fs.StringVar(&stats_dst, "report_dest", "", "Specify where the stats data should be sent. It can be local file or remote POST address(starts with http:// or https://)")
            fs.Int64Var(&retry_times, "retry_times", 0, `If a connection received stopped events or fails for any reason, it will retry a specified number of times, default value is 0. If a negative value is provided, it retries forever.`)
        }
    }()

    ws.StringVar(&viewer_url, "url", "", "Viewer URL to access [ws]")
    ws.BoolVar(&wait_on_inactive, "wait_on_inactive", false, "A boolean flag, if set, the program will wait when server turns inactive, otherwise just exit [ws]")

    rtcbackup.Uint64Var(&ptkid, "ptoken_id", 0, "Specify the publish token id [rtcbackup]")
    rtcbackup.Uint64Var(&stkid, "stoken_id", 0, "Specify the subscribe token id [rtcbackup]")
    rtcbackup.StringVar(&ptoken, "ptoken", "", "Specify the publish token [rtcbackup]")
    rtcbackup.StringVar(&stoken, "stoken", "", "Specify the subscribe token [rtcbackup]")
    rtcbackup.StringVar(&accountId, "account_id", "", "Specify the account id [rtcbackup]")
    rtcbackup.StringVar(&streamName, "stream_name", "", "Specify the stream name [rtcbackup]")
    rtcbackup.StringVar(&platform, "platform", "dev", "It can be 'dev', 'staging' or 'production' [rtcbackup]")

    var cfg AppCfg

    switch os.Args[1] {
    case "rb":
        rtcbackup.Parse(os.Args[2:])
        cfg.rtcbackup_cfg.ptoken = &ptoken
        cfg.rtcbackup_cfg.stoken = &stoken
        cfg.rtcbackup_cfg.ptoken_id = ptkid
        cfg.rtcbackup_cfg.stoken_id = stkid
        cfg.rtcbackup_cfg.platform = &platform
        if *cfg.rtcbackup_cfg.platform == "production" {
            *cfg.rtcbackup_cfg.platform = ""
        } else if *cfg.rtcbackup_cfg.platform != "dev" && *cfg.rtcbackup_cfg.platform != "staging" {
            log.Fatalf("Unknown platform: %s", *cfg.rtcbackup_cfg.platform)
        } else {
            *cfg.rtcbackup_cfg.platform = "-" + *cfg.rtcbackup_cfg.platform
        }
        cfg.streamAccountId = accountId
        cfg.streamName = streamName
        cfg.rtcbackup = true
    case "ws":
        ws.Parse(os.Args[2:])
        cfg.wait_on_inactive = wait_on_inactive
        cfg.viewer_url = &viewer_url
        if *cfg.viewer_url == "" {
            log.Fatal("URL is not specified, exit")
        }

    default:
        log.Fatalf("Unknown subcommand '%s', please check the help info", os.Args[1])
    }

    cfg.codec = &codec
    cfg.pion_dbg = pion_dbg
    cfg.test_name = &test_name


    if level, ok := logLevelTable[logLevel]; ok {
        log.SetLevel(level)
    } else {
        log.Fatal("Unrecognized log level, exit")
    }

    if num <= 0 {
        log.Fatal("Specify a positive number for connections!")
    }

    if cfg.rtcbackup {
        if *cfg.rtcbackup_cfg.stoken == "" || cfg.rtcbackup_cfg.stoken_id == 0 || *cfg.rtcbackup_cfg.ptoken == "" || cfg.rtcbackup_cfg.ptoken_id == 0 {
            log.Fatal("Must specify pub/sub token and token id")
        }

        if cfg.streamAccountId == "" || cfg.streamName == "" {
            log.Fatal("Must specify accountId/streamName")
        }
        // we calculate appId and appKey here as this only needs to be done once
        // but later we'll use them to generate jwt token for each connection as that has a timing effect (expire in some time)
        cfg.rtcbackup_cfg.appId = generate_appid(cfg.streamAccountId, cfg.rtcbackup_cfg.ptoken_id, cfg.rtcbackup_cfg.stoken_id)
        cfg.rtcbackup_cfg.appKey = generate_appkey(cfg.rtcbackup_cfg.ptoken, cfg.rtcbackup_cfg.stoken)

        // we should have enough information to figure out the view url, it is printed out for convenience
        check_url_tpl := "https://viewer%v.millicast.com/?streamId=%v/%v&token=%v"
        special_rtcbackup_name := generate_rtcbackup_name(cfg.rtcbackup_cfg.ptoken_id, cfg.rtcbackup_cfg.stoken_id, &cfg.streamName)
        check_url := fmt.Sprintf(check_url_tpl, *cfg.rtcbackup_cfg.platform, cfg.streamAccountId, special_rtcbackup_name, *cfg.rtcbackup_cfg.stoken);
        fmt.Println("View URL:\n", check_url)
    } else {
        // we extract account id and stream name from the url
        m := parse(cfg.viewer_url)
        if _, ok := m["streamAccountId"]; !ok {
            log.Fatal("Failed to extract streamAccountId from URL: ", *cfg.viewer_url)
        }
        if _, ok := m["streamName"]; !ok {
            log.Fatal("Failed to extract streamName from URL: ", *cfg.viewer_url)
        }
        cfg.streamAccountId = m["streamAccountId"]
        cfg.streamName = m["streamName"]
    }

    if logfile != "" {
        f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
        if err != nil {
            log.Fatal("Failed to open log file, exit")
        }
        log.SetOutput(f)
    }

    cur := time.Now()
    if *cfg.test_name == "" {
        *cfg.test_name = cur.Format("2006-01-02_15:04:05_") + genRandomHash(4)
    }

    if stats_dst == "" {
        stats_dst = cur.Format("2006-01-02_15:04:05.stats.txt")
    } else if strings.HasPrefix(stats_dst, "http://") || strings.HasPrefix(stats_dst, "https://") {
        send_stats = send_stats_post
    }

    if report_interval < 0 {
        stats_report_interval = 10
    } else {
        stats_report_interval = report_interval
    }

    if max_connecting > 0 {
        cfg.max_concurrent_connecting = max_connecting
        // note: it's buffered channel, with fixed length "max_concurrent_connecting"
        _c := make(chan struct{}, cfg.max_concurrent_connecting)
        cfg.rate_limit_connecting = &_c
        for i := 0; i < int(cfg.max_concurrent_connecting); i++ {
            *cfg.rate_limit_connecting <- struct{}{}
        }
        if connecting_time > 0 {
            log.Debug("connecting_time is disabled as max_connecting is specified")
            connecting_time = 0
        }
    }

    // we make the channel with plent of buffer
    c := make(chan []byte, num)
    cfg.stats_ch = &c
    go notify_send_stats(*cfg.stats_ch, stats_dst)

    // we'll need to call rand soon, let's do seed here
    rand.Seed(time.Now().UnixNano())

    wg := new(sync.WaitGroup)
    wg.Add(num)

    conn_interval := 0.0
    if connecting_time > 0 {
        conn_interval = float64(connecting_time) / float64(num)
    }

    before_connect := time.Now()
    for i := 0; i < num; i++ {
        connect(wg, i, &cfg, retry_times)
        if conn_interval > 0 && i != num - 1 {
            time.Sleep(time.Duration(conn_interval * 1e9))
        }
    }
    log.Info("The total connecting time(s): ", float64(time.Since(before_connect))/1e9)

    wg.Wait()
    log.Info("Scale client exit")
}
