package main

import (
    "flag"
    log "github.com/sirupsen/logrus"
    "os"
)


func task() {

}

func main() {
    logLevelTable := map[string]log.Level {
        "panic": log.PanicLevel,
		"error": log.ErrorLevel,
		"warn":  log.WarnLevel,
		"info":  log.InfoLevel,
		"debug": log.DebugLevel,
    }


    url := flag.String("u", "", "URL to access")
    // num := flag.Int("n", 10, "Number of connections")
    // prefix := flag.String("p", "client", "Prefix to help identify connections, e.g. if we use \"client\" as prefix, we may have client_1, client_2 ...") 
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

    if *logfile != "" {
        f, err := os.OpenFile(*logfile, os.O_RDWR|os.O_CREATE, 0666)
        if err != nil {
            log.Fatal("Failed to open log file, exit")
        }
        log.SetOutput(f)
    }
    

	interrupt := make(chan os.Signal, 1)

    go connect(*url)

	// main goroutine is waiting here until the user chooses to exit
	select {
	case <-interrupt:
		log.Info("Interrupted!")
		break
	}
    log.Info("Scale client exit")
}
