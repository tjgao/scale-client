package main

import (
    "bytes"
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    rd "crypto/rand"
    "crypto/sha256"
    "crypto/tls"
    "fmt"
    "sync"
    "sync/atomic"

    "encoding/json"
    "io/ioutil"

    "errors"
    "net/http"
    "net/url"
    "regexp"
    "strings"
    "time"

    "github.com/gorilla/websocket"
    "github.com/pion/ice/v2"
    "github.com/pion/interceptor"
    "github.com/pion/interceptor/pkg/stats"
    "github.com/pion/logging"
    "github.com/pion/webrtc/v3"

    log "github.com/sirupsen/logrus"
)

const MAX_RTP_LEN = 2000

type ReqJson struct {
    StreamAccountId string `json:"streamAccountId"`
    StreamName      string `json:"streamName"`
}

type SubscribeResp struct {
    Url        string
    Jwt        string
    IceServers []webrtc.ICEServer
}

type TransCommand struct {
    Type    string                 `json:"type"`
    TransId int                    `json:"transId"`
    Name    string                 `json:"name"`
    Data    map[string]interface{} `json:"data"`
}

type TransCommandResp struct {
    Type    string            `json:"type"`
    TransId int               `json:"transId"`
    Data    map[string]string `json:"data"`
}

type RunningState struct {
    cid        int                // an integer to identifiy a connection
    Cert       webrtc.Certificate // local cert
    LocalUser  string             // ice user
    LocalPwd   string             // ice pwd
    SubResp    *SubscribeResp     // subscribe response
    connecting atomic.Bool
    local_sdp  string
    conn_exit  chan struct{}
}

func lerror(args ...interface{}) {
    left := args[1:]
    log.Error("(", args[0], ") ", left)
}

func linfo(args ...interface{}) {
    left := args[1:]
    log.Info("(", args[0], ") ", left)
}

func ldebug(args ...interface{}) {
    left := args[1:]
    log.Debug("(", args[0], ") ", left)
}

const subscribe_url string = "https://director%v.millicast.com/api/director/subscribe"

// parse the url to get stream account id and name
func parse(url string) map[string]string {
    re := regexp.MustCompile("http.+streamId=(?P<streamAccountId>[0-9a-zA-Z]+)/(?P<streamName>[0-9a-zA-Z]+)")
    r := re.FindAllStringSubmatch(url, -1)[0]
    keys := re.SubexpNames()
    md := map[string]string{}
    for i, n := range r {
        md[keys[i]] = n
    }
    return md
}

func addIceServer(o interface{}, sub *SubscribeResp) {
    var ice webrtc.ICEServer
    m := o.(map[string]interface{})
    if u, ok := m["urls"]; ok {
        _u := u.([]interface{})
        for _, uu := range _u {
            ice.URLs = append(ice.URLs, uu.(string))
        }
    } else {
        log.Error("Empty ice server json object")
        return
    }

    if n, ok := m["username"]; ok {
        ice.Username = n.(string)
    }

    if c, ok := m["credential"]; ok {
        ice.Credential = c.(string)
    }

    sub.IceServers = append(sub.IceServers, ice)
}

func check_result(result map[string]interface{}) *SubscribeResp {
    var sub SubscribeResp
    if status, ok := result["status"]; !ok || status != "success" {
        log.Error("The response status is not 'success', it is ", status)
        return nil
    }

    if d, ok := result["data"]; ok {
        data := d.(map[string]interface{})

        if j, ok := data["jwt"]; ok {
            sub.Jwt = j.(string)
        } else {
            log.Error("Found no jwt in json")
            return nil
        }
        if u, ok := data["wsUrl"]; ok {
            sub.Url = u.(string)
        } else {
            log.Error("Found no wsUrl in json")
            return nil
        }
        if m, ok := data["iceServers"]; ok {
            mm := m.([]interface{})
            for _, i := range mm {
                addIceServer(i, &sub)
            }
        } else {
            log.Debug("Found no ice servers in json")
        }
    }

    return &sub
}

func convertTypeFromICE(t ice.CandidateType) (webrtc.ICECandidateType, error) {
    switch t {
    case ice.CandidateTypeHost:
        return webrtc.ICECandidateTypeHost, nil
    case ice.CandidateTypeServerReflexive:
        return webrtc.ICECandidateTypeSrflx, nil
    case ice.CandidateTypePeerReflexive:
        return webrtc.ICECandidateTypePrflx, nil
    case ice.CandidateTypeRelay:
        return webrtc.ICECandidateTypeRelay, nil
    default:
        return webrtc.ICECandidateType(t), errors.New("Unknown ICE candidate type")
    }
}

func newICECandidateFromICE(i ice.Candidate) (webrtc.ICECandidate, error) {
    typ, err := convertTypeFromICE(i.Type())
    if err != nil {
        return webrtc.ICECandidate{}, err
    }
    protocol, err := webrtc.NewICEProtocol(i.NetworkType().NetworkShort())
    if err != nil {
        return webrtc.ICECandidate{}, err
    }

    c := webrtc.ICECandidate{
        Foundation: i.Foundation(),
        Priority:   i.Priority(),
        Address:    i.Address(),
        Protocol:   protocol,
        Port:       uint16(i.Port()),
        Component:  i.Component(),
        Typ:        typ,
        TCPType:    i.TCPType().String(),
    }

    if i.RelatedAddress() != nil {
        c.RelatedAddress = i.RelatedAddress().Address
        c.RelatedPort = uint16(i.RelatedAddress().Port)
    }

    return c, nil
}

func create_ice_connection(st *RunningState, info *AnswerSDPInfo) *ice.Conn {
    iceAgent, err := ice.NewAgent(&ice.AgentConfig{
        NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4},
        LocalUfrag:   st.LocalUser,
        LocalPwd:     st.LocalPwd,
    })
    if err != nil {
        panic(err)
    }

    // It seems fine if the line below is removed
    iceAgent.SetRemoteCredentials(info.Ice.Ufrag, info.Ice.Pwd)

    for _, i := range info.Candidates {
        log.Debug(i)
        c, err := ice.UnmarshalCandidate(i)
        if err != nil {
            panic(err)
        }
        iceAgent.AddRemoteCandidate(c)
    }

    if err = iceAgent.OnCandidate(func(c ice.Candidate) {}); err != nil {
        panic(err)
    }

    if err = iceAgent.GatherCandidates(); err != nil {
        panic(err)
    }

    iceAgent.OnConnectionStateChange(func(state ice.ConnectionState) {
        log.Debug("ice state changed to ", state)
    })
    conn, err := iceAgent.Dial(context.TODO(), info.Ice.Ufrag, info.Ice.Pwd)
    if err != nil {
        log.Error("Failed to create ICE connection: ", err)
    }

    return conn
}

// This uses PeerConnection which has better encapsulation
// it also dynmically generates answer SDP
func receive_streaming(cfg *AppCfg, st *RunningState, info *AnswerSDPInfo) {
    if cfg.rate_limit_connecting != nil {
        defer func() {
            b := st.connecting.Load()
            if b {
                st.connecting.Store(false)
                *cfg.rate_limit_connecting <- struct{}{}
            }
        }()
    }

    var err error
    m := &webrtc.MediaEngine{}

    videoRTCPFeedback := []webrtc.RTCPFeedback{
        {Type: "goog-remb", Parameter: ""},
        {Type: "ccm", Parameter: "fir"},
        {Type: "nack", Parameter: ""},
        {Type: "nack", Parameter: "pli"},
        {Type: "transport-cc", Parameter: ""},
    }

    fmtp_line := ""
    mime_type := webrtc.MimeTypeH264
    clock_rate := 90000
    payload_type := 0

    switch {
    case *cfg.codec == "h264":
        fmtp_line = "packetization-mode=1"
        clock_rate = 90000
        mime_type = webrtc.MimeTypeH264
        payload_type = 102
    case *cfg.codec == "vp8":
        fmtp_line = ""
        clock_rate = 90000
        mime_type = webrtc.MimeTypeVP8
        payload_type = 96
    case *cfg.codec == "vp9":
        fmtp_line = ""
        clock_rate = 90000
        mime_type = webrtc.MimeTypeVP9
        payload_type = 98
    default:
        panic(errors.New(fmt.Sprintf("Unknown codec: %v", *cfg.codec)))
    }

    err = m.RegisterCodec(
        webrtc.RTPCodecParameters{RTPCodecCapability: webrtc.RTPCodecCapability{
            MimeType: mime_type, ClockRate: uint32(clock_rate), Channels: 0,
            SDPFmtpLine:  fmtp_line,
            RTCPFeedback: videoRTCPFeedback,
        },
            PayloadType: webrtc.PayloadType(payload_type)}, webrtc.RTPCodecTypeVideo)
    if err != nil {
        panic(err)
    }

    err = m.RegisterCodec(
        webrtc.RTPCodecParameters{
            RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 0},
            PayloadType:        115}, webrtc.RTPCodecTypeAudio)
    if err != nil {
        panic(err)
    }

    var g stats.Getter
    statsIntFactory, err := stats.NewInterceptor()
    if err != nil {
        panic(err)
    }
    statsIntFactory.OnNewPeerConnection(func(s string, getter stats.Getter) {
        g = getter
    })

    ic := &interceptor.Registry{}
    ic.Add(statsIntFactory)
    if err := webrtc.RegisterDefaultInterceptors(m, ic); err != nil {
        panic(err)
    }

    s := webrtc.SettingEngine{}
    s.SetICECredentials(st.LocalUser, st.LocalPwd)
    s.SetICETimeouts(5 * time.Second, 25 * time.Second, 500 * time.Millisecond)
    if cfg.pion_dbg {
        lf := logging.NewDefaultLoggerFactory()
        lf.DefaultLogLevel = logging.LogLevelDebug
        s.LoggerFactory = lf
    }
    api := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithSettingEngine(s), webrtc.WithInterceptorRegistry(ic))

    wcfg := webrtc.Configuration{
        Certificates: []webrtc.Certificate{st.Cert},
    }

    pc, err := api.NewPeerConnection(wcfg)
    if err != nil {
        log.Fatal("Failed to create peer connection: ", err)
    }

    var ice_state webrtc.ICEConnectionState = webrtc.ICEConnectionStateNew
    var conn_state webrtc.PeerConnectionState = webrtc.PeerConnectionStateNew

    pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
        ldebug(st.cid, "ice connection state changed to ", state)
        ice_state = state
    })

    pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
        ldebug(st.cid, "connection state switched to ", state)
        conn_state = state
    })

    _, err = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly})
    if err != nil {
        panic(err)
    }
    _, err = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly})
    if err != nil {
        panic(err)
    }

    pc.OnTrack(func(tr *webrtc.TrackRemote, rc *webrtc.RTPReceiver) {
        go func() {
            b := make([]byte, MAX_RTP_LEN)
            for {
                _, _, err := tr.Read(b)
                if err != nil {
                    ldebug(st.cid, fmt.Sprintf("RTP read goroutine for %v: %v exit", tr.Kind().String(), tr.SSRC()))
                    break
                }
            }
        }()

        go func() {
            b := make([]byte, MAX_RTP_LEN)
            for {
                _, _, err := rc.Read(b)
                if err != nil {
                    ldebug(st.cid, "RTCP read goroutine exit")
                    break
                }
            }
        }()
    })

    offer, err := pc.CreateOffer(nil)
    if err != nil {
        panic(err)
    }

    if err = pc.SetLocalDescription(offer); err != nil {
        panic(err)
    }

    remote := webrtc.SessionDescription{SDP: info.orig_sdp, Type: webrtc.SDPTypeAnswer}
    if err = pc.SetRemoteDescription(remote); err != nil {
        panic(err)
    }

    go func() {
        last_stats := map[webrtc.SSRC]stats.InboundRTPStreamStats{}
        for {
            select {
            case <-st.conn_exit:
                pc.Close()
                ldebug(st.cid, "close peerconnection")
                return
            case <-time.After(time.Second * time.Duration(stats_report_interval)):
                ts := pc.GetTransceivers()
                rpt := fmt.Sprintf("{\"userId\":\"%v\"", st.LocalUser)
                rpt += fmt.Sprintf(", \"TestName\":\"%v\"", *cfg.test_name)
                rpt += fmt.Sprintf(", \"ICE_State\":\"%v\"", ice_state.String())
                rpt += fmt.Sprintf(", \"Conn_State\":\"%v\"", conn_state.String())
                videos := []string{}
                audios := []string{}
                remote := ""
                for _, t := range ts {
                    tk := t.Receiver().Track()
                    ssrc := tk.SSRC()
                    o := fmt.Sprintf("{\"SSRC\":%v", ssrc)
                    o += fmt.Sprintf(", \"Type\":\"%v\"", tk.Kind().String())
                    r := g.Get(uint32(ssrc))
                    if r != nil {
                        o += fmt.Sprintf(", \"PacketReceived\":%v", r.InboundRTPStreamStats.PacketsReceived)
                        o += fmt.Sprintf(", \"PacketLost\":%v", r.InboundRTPStreamStats.PacketsLost)
                        o += fmt.Sprintf(", \"Jitter\":%v", r.InboundRTPStreamStats.Jitter)
                        o += fmt.Sprintf(", \"LastPacketReceivedTimestamp\":%f", float64(r.InboundRTPStreamStats.LastPacketReceivedTimestamp.UnixNano())/1000000000.0)
                        o += fmt.Sprintf(", \"HeaderBytesReceived\":%v", r.InboundRTPStreamStats.HeaderBytesReceived)
                        o += fmt.Sprintf(", \"BytesReceived\":%v", r.InboundRTPStreamStats.BytesReceived)
                        o += fmt.Sprintf(", \"NACKCount\":%v", r.InboundRTPStreamStats.NACKCount)
                        o += fmt.Sprintf(", \"PLICount\":%v", r.InboundRTPStreamStats.PLICount)
                        o += fmt.Sprintf(", \"FIRCount\":%v", r.InboundRTPStreamStats.FIRCount)
                        last, ok := last_stats[ssrc]
                        packets_loss_percentage := float64(0)
                        bitrate := float64(0)
                        if ok {
                            packets_lost := float64(r.InboundRTPStreamStats.PacketsLost - last.PacketsLost)
                            packets_received := float64(r.InboundRTPStreamStats.PacketsReceived - last.PacketsReceived)
                            packets_loss_percentage = 100.0 * packets_lost / packets_received
                            bytes_received := float64(r.InboundRTPStreamStats.BytesReceived - last.BytesReceived)
                            time_diff := float64(r.InboundRTPStreamStats.LastPacketReceivedTimestamp.Sub(last.LastPacketReceivedTimestamp).Seconds())
                            bitrate = (8 * bytes_received / time_diff) / 1024.0
                        }
                        o += fmt.Sprintf(", \"PacketLossPercentage\":%.2f", packets_loss_percentage)
                        o += fmt.Sprintf(", \"Bitrate\":%.2f", bitrate)
                        last_stats[ssrc] = r.InboundRTPStreamStats
                    }
                    o += "}"
                    if tk.Kind() == webrtc.RTPCodecTypeAudio {
                        audios = append(audios, o)
                    } else {
                        videos = append(videos, o)
                    }
                    if remote == "" {
                        remote += "{"
                        if r != nil {
                            remote += fmt.Sprintf("\"BytesSent\":%v", r.RemoteOutboundRTPStreamStats.BytesSent)
                            remote += fmt.Sprintf(", \"PacketsSent\":%v", r.RemoteOutboundRTPStreamStats.PacketsSent)
                            remote += fmt.Sprintf(", \"ReportsSent\":%v", r.RemoteOutboundRTPStreamStats.ReportsSent)
                            remote += fmt.Sprintf(", \"RoundTripTime\":\"%v\"", r.RemoteOutboundRTPStreamStats.RoundTripTime)
                            remote += fmt.Sprintf(", \"RemoteTimeStamp\":%f", float64(r.RemoteOutboundRTPStreamStats.RemoteTimeStamp.UnixNano())/1000000000.0)
                            remote += fmt.Sprintf(", \"TotalRoundTripTime\":\"%v\"", r.RemoteOutboundRTPStreamStats.TotalRoundTripTime)
                            remote += fmt.Sprintf(", \"RoundTripTimeMeasurements\":%v", r.RemoteOutboundRTPStreamStats.RoundTripTimeMeasurements)
                        }
                        remote += "}"
                    }
                }
                videos_str := "["
                for i, v := range videos {
                    if i != 0 {
                        videos_str += ","
                    }
                    videos_str += v
                }
                videos_str += "]"
                rpt += fmt.Sprintf(", \"VideoStreams\":%v", videos_str)

                audios_str := "["
                for i, a := range audios {
                    if i != 0 {
                        audios_str += ","
                    }
                    audios_str += a
                }
                audios_str += "]"
                rpt += fmt.Sprintf(", \"AudioStreams\":%v", audios_str)
                rpt += fmt.Sprintf(", \"RemoteOutboundRTPStreamStats\":%v", remote)
                rpt += "}\n"

                *cfg.stats_ch <- []byte(rpt)
            }
        }
    }()
}

// This is a way to directly manipulate transport objects and ice gather object
// It also takes advantage of a SDP template
func receive_streaming_direct(cfg *AppCfg, st *RunningState, info *AnswerSDPInfo) {
    if cfg.rate_limit_connecting != nil {
        defer func() {
            b := st.connecting.Load()
            if b {
                st.connecting.Store(false)
                *cfg.rate_limit_connecting <- struct{}{}
            }
        }()
    }
    // prepare ICE gathering options
    iceOptions := webrtc.ICEGatherOptions{ICEServers: st.SubResp.IceServers}

    s := webrtc.SettingEngine{}
    s.SetICECredentials(st.LocalUser, st.LocalPwd)
    s.SetAnsweringDTLSRole(webrtc.DTLSRoleClient)

    api := webrtc.NewAPI(webrtc.WithSettingEngine(s))

    gatherer, err := api.NewICEGatherer(iceOptions)
    if err != nil {
        panic(err)
    }

    ice_transport := api.NewICETransport(gatherer)

    // Create DTLS transport, use our cert
    dtls_transport, err := api.NewDTLSTransport(ice_transport, []webrtc.Certificate{st.Cert})
    if err != nil {
        panic(err)
    }

    rtp_receiver, err := api.NewRTPReceiver(webrtc.RTPCodecTypeVideo, dtls_transport)
    if err != nil {
        panic(err)
    }

    gatherFinished := make(chan struct{})
    gatherer.OnLocalCandidate(func(i *webrtc.ICECandidate) {
        if i == nil {
            close(gatherFinished)
        } else {
            // ldebug(st.cid, "add one candidate: ", i.String())
        }
    })

    // Gather candidates
    err = gatherer.Gather()
    if err != nil {
        panic(err)
    }

    <-gatherFinished

    // Add remote candidates into ice transport
    for _, i := range info.Candidates {
        c, err := ice.UnmarshalCandidate(i)
        if err != nil {
            panic(err)
        }
        cc, err := newICECandidateFromICE(c)
        if err != nil {
            panic(err)
        }
        ice_transport.AddRemoteCandidate(&cc)
    }

    ice_transport.OnConnectionStateChange(func(state webrtc.ICETransportState) {
        ldebug(st.cid, "ICE state changed to ", state)
    })
    ice_transport.OnSelectedCandidatePairChange(func(p *webrtc.ICECandidatePair) {
        ldebug(st.cid, "ICE candidate pair changed ", p)
    })

    iceRole := webrtc.ICERoleControlling
    err = ice_transport.Start(gatherer, webrtc.ICEParameters{UsernameFragment: info.Ice.Ufrag, Password: info.Ice.Pwd, ICELite: info.Ice.Lite}, &iceRole)
    if err != nil {
        panic(err)
    }

    dtls_transport.OnStateChange(func(state webrtc.DTLSTransportState) {
        ldebug(st.cid, "DTLS state changed to ", state)
    })

    err = dtls_transport.Start(webrtc.DTLSParameters{Role: webrtc.DTLSRoleServer,
        Fingerprints: []webrtc.DTLSFingerprint{{Algorithm: info.Dtls.Hash, Value: info.Dtls.Fingerprint}}})
    if err != nil {
        panic(err)
    }

    err = rtp_receiver.Receive(info.RTPRecvParams)
    if err != nil {
        panic(err)
    }

    ldebug(st.cid, "Connection is working")
}

func on_event(cfg *AppCfg, st *RunningState, buf []byte) bool {
    var ev map[string]interface{}
    err := json.Unmarshal(buf, &ev)
    if err != nil {
        // even though we received some weird json, we are staying
        lerror(st.cid, "Failed to unmarshal received json: ", string(buf))
        return true
    }

    var info *AnswerSDPInfo = nil
    if e, ok := ev["type"]; !ok {
        lerror(st.cid, "Unrecognized json: ", string(buf))
    } else {
        if e == "response" {
            if data, ok := ev["data"]; !ok {
                lerror(st.cid, "Found no data in the response json: ", string(buf))
                return false
            } else {
                if info == nil {
                    m := data.(map[string]interface{})
                    sdp := m["sdp"].(string)
                    info = readAnswerSDP(sdp)
                    if info == nil {
                        lerror(st.cid, "Failed to extract all info from sdp")
                        return false
                    }
                }
                // go receive_streaming_direct(cfg, st, info)
                go receive_streaming(cfg, st, info)
            }
        } else {
            if n, ok := ev["name"]; !ok {
                lerror(st.cid, "No name for this event: ", string(buf))
            } else {
                if n == "stopped" {
                    linfo(st.cid, fmt.Sprintf("Server stopped streaming: %v", string(buf)))
                    return false
                } else if n == "inactive" {
                    // This means the server temporarily pauses streaming
                    // but as long as the DTLS connection is still alive, we do not need to do anything
                    // because when server starts streaming again,  DTLS conn will just work
                    // linfo(st.cid, "Server is inactive")
                    // if wait_on_inactive is true, we'll stay
                    ldebug(st.cid, "Server is inactive")
                    return cfg.wait_on_inactive
                } else if n == "active" {
                    /// This means the server continues streaming
                    // linfo(st.cid, "Server is active")
                } else {
                    // ldebug(st.cid, "Received ws message: ", string(buf))
                }
            }
        }
    }
    return true
}

func get_fingerprint(cert tls.Certificate) string {
    var buf bytes.Buffer
    fp := sha256.Sum256(cert.Certificate[0])
    for i, b := range fp {
        if i == 0 {
            buf.WriteString(fmt.Sprintf("%02X", b))
        } else {
            buf.WriteString(fmt.Sprintf(":%02X", b))
        }
    }
    return buf.String()
}

func connect(wg *sync.WaitGroup, cid int, cfg *AppCfg, retry uint64) {
    defer wg.Done()
    m := parse(*cfg.viewer_url)
    if _, ok := m["streamAccountId"]; !ok {
        log.Fatal("Failed to extract streamAccountId from URL: ", *cfg.viewer_url)
    }
    if _, ok := m["streamName"]; !ok {
        log.Fatal("Failed to extract streamName from URL: ", *cfg.viewer_url)
    }

    // Generate a random privateKey
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rd.Reader)
    if err != nil {
        log.Fatal("Failed to generate private key for DTLS: ", err)
    }
    // Generate cert for DTLS
    cert, err := webrtc.GenerateCertificate(priv)

    if err != nil {
        log.Fatal("Failed to generate cert for DTLS: ", err)
    }

    fingerprint, err := cert.GetFingerprints()
    if err != nil {
        log.Fatal("Failed to calculate fingerprint from cert: ", err)
    }

    var state = RunningState{cid: cid, Cert: *cert, LocalUser: genRandomHash(16), LocalPwd: genRandomHash(48)}


    req_sdp := createReqSDP(state.LocalUser, state.LocalPwd, "sha-256", fingerprint[0].Value)
    state.local_sdp = req_sdp

    // try to get the permissio to do connecting if needed
    if cfg.rate_limit_connecting != nil {
        <-*cfg.rate_limit_connecting
        state.connecting.Store(true)
        // The reason we do this is , it is possible it may not have the chance
        // to call receive_rtp_streaming so we won't be able to notify the channel
        // we've finished connecting
        defer func() {
            b := state.connecting.Load()
            if b {
                state.connecting.Store(false)
                *cfg.rate_limit_connecting <- struct{}{}
            }
        }()
    }

    client := &http.Client{}
    // resp, err := client.Get(*cfg.viewer_url)
    // if err != nil {
    //     log.Fatal("Failed to access url: ", err)
    // }
    //
    // resp.Body.Close()

    domain_splits :=  strings.Split(strings.Split(*cfg.viewer_url, ".")[0], "-")
    domain := ""
    if len(domain_splits) > 1 {
        for _, s := range domain_splits[1:] {
            domain += "-"
            domain += s
        }
    } 

    sub_url := fmt.Sprintf(subscribe_url, domain)


    for {
        streamName := m["streamName"]
        // we now send json request to the subscribe url
        var reqJson = ReqJson{StreamAccountId: m["streamAccountId"], StreamName: m["streamName"]}
        bs, err := json.Marshal(&reqJson)
        if err != nil {
            log.Fatal("Failed to marshal json data: ", err)
        }

        // sometimes, especially a bunch of connections are created, server may return 
        // error, so we'll try a few times with pause
        var sub *SubscribeResp
        req, err := http.NewRequest("POST", sub_url, bytes.NewBuffer(bs))
        req.Header.Set("Content-Type", "application/json")
        for _i := 0; _i<5; _i++ {
            if _i > 0 {
                time.Sleep(1 * time.Second)
            }
            resp, err := client.Do(req)
            if err != nil {
                log.Error("Failed to post request json to url: ", sub_url, ",  err: ", err)
                continue
            }

            body, err := ioutil.ReadAll(resp.Body)
            if err != nil {
                log.Error("Failed to read data from response, err: ", err)
                continue
            }

            var result map[string]interface{}
            err = json.Unmarshal(body, &result)
            if err != nil {
                log.Error("Failed to unmarshal returned response json: ", body)
                continue
            }

            sub = check_result(result)
            if sub == nil {
                log.Error("Server's response is not valid:", string(body))
                continue
            } else {
                state.SubResp = sub
            }
            break
        }
        if sub == nil {
            log.Fatal("Server returns error all the time, stop trying")
        }
        wss_url, err := url.Parse(sub.Url + "?token=" + sub.Jwt)

        if err != nil {
            log.Fatal("The wss url seems to be invalid: ", err)
        }

        // we now visit wss url
        conn, _, err := websocket.DefaultDialer.Dial(wss_url.String(), nil)
        if err != nil {
            log.Fatal("Failed to connect websocket url: ", wss_url.String())
        }
        defer conn.Close()

        // prepare json
        _events := []string{"active", "inactive", "layers", "viewercount"}
        var sdp_mp = map[string]interface{}{"sdp": req_sdp, "streamId": streamName, "events": _events}
        var cmd = TransCommand{Type: "cmd", TransId: 0, Name: "view", Data: sdp_mp}
        bs, err = json.Marshal(&cmd)
        if err != nil {
            log.Fatal("Failed to marshal json data: ", err)
        }

        // Send view command
        err = conn.WriteMessage(websocket.TextMessage, bs)
        if err != nil {
            log.Fatal("Failed to send sdp via websocket connection: ", err)
        }

        state.conn_exit = make(chan struct{}) 

        // Now wait for response and other events
        for {
            t, buf, err := conn.ReadMessage()
            if err != nil {
                lerror(cid, "Failed to read message from websocket: ", err)
                break
            }
            if t == websocket.TextMessage {
                if !on_event(cfg, &state, buf) {
                    close(state.conn_exit)
                    linfo(cid, "Connection task exit")
                    break
                }
            } else {
                // we recieved binary
                ldebug(cid, "Received binary data message")
            }
        }
        if retry == 0 {
            break
        } else {
            retry--
        }
    }
}
