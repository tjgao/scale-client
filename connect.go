package main

import (
    "bytes"
    b64 "encoding/base64"
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
    ws_exit  *chan struct{}
    rtp_exit   *chan struct{}
    rtcp_exit   *chan struct{}
}

type ConnectStats struct {
    UserID string                `json:"userId"`
    TestName string              `json:"TestName"`
    HttpSubscribe float64        `json:"httpSubscribe"`
    ICESetup float64             `json:"iceSetup"`
    DTLSSetup float64            `json:"dtlsSetup"`
    // SDPOffer float64             `json:"sdpOffer"`
    // SDPAnswer float64            `json:"sdpAnswer"`
    FirstFrame float64           `json:"firstFrame"`
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
func receive_streaming(cfg *AppCfg, st *RunningState, cs *ConnectStats, answer_sdp *string) {
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
    if cfg.pion_dbg {
        lf := logging.NewDefaultLoggerFactory()
        lf.DefaultLogLevel = logging.LogLevelInfo
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

    iceStart := time.Now()
    dtlsStart := iceStart
    firstFrame := dtlsStart
    iceConnected := false
    dtlsConnected := false
    firstFrameReceived := false
    pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
        ldebug(st.cid, "ice connection state changed to ", state)
        ice_state = state
        if ice_state == webrtc.ICEConnectionStateFailed {
            lerror(st.cid, "ice connection failed, close peerconnection")
            pc.Close()
        }
        if (!iceConnected && ice_state == webrtc.ICEConnectionStateConnected) {
            iceConnected = true
            cs.ICESetup = (float64(time.Since(iceStart)))/1000000.0
            dtlsStart = time.Now()
        }
    })


    pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
        ldebug(st.cid, "connection state switched to ", state)
        conn_state = state
        if conn_state == webrtc.PeerConnectionStateFailed {
            lerror(st.cid, "connection failed, close peerconnection")
            pc.Close()
        }
        if (!dtlsConnected && iceConnected && state == webrtc.PeerConnectionStateConnected) {
            dtlsConnected = true;
            cs.DTLSSetup = (float64(time.Since(dtlsStart)))/1000000.0
            firstFrame = time.Now()
        }
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
        rtp_ch := st.rtp_exit
        rtcp_ch := st.rtcp_exit
        go func() {
            rtp_buf := make([]byte, MAX_RTP_LEN)
            for {
                _, _, err := tr.Read(rtp_buf)
                if err != nil {
                    ldebug(st.cid, fmt.Sprintf("RTP read goroutine for %v: %v exit", tr.Kind().String(), tr.SSRC()))
                    break
                }
                if (!firstFrameReceived) {
                    firstFrameReceived = true
                    cs.FirstFrame = (float64(time.Since(firstFrame)))/1000000.0
                    // we'll send the connect stats now
                    bs, err := json.Marshal(cs)
                    if err == nil {
                        bs = append(bs, byte('\n'))
                        *cfg.stats_ch <- bs
                    }
                }
            }
            pc.Close()
            close(*rtp_ch)
        }()

        go func() {
            rtcp_buf := make([]byte, MAX_RTP_LEN)
            for {
                _, _, err := rc.Read(rtcp_buf)
                if err != nil {
                    ldebug(st.cid, fmt.Sprintf("RTCP read goroutine for %v: %v exit", rc.Track().Kind().String(), rc.Track().SSRC()))
                    break
                }
            }
            pc.Close()
            close(*rtcp_ch)
        }()
    })

    offer, err := pc.CreateOffer(nil)
    if err != nil {
        panic(err)
    }

    if err = pc.SetLocalDescription(offer); err != nil {
        panic(err)
    }

    remote := webrtc.SessionDescription{SDP: *answer_sdp, Type: webrtc.SDPTypeAnswer}
    if err = pc.SetRemoteDescription(remote); err != nil {
        panic(err)
    }

    go func() {
        rtp_ch := st.rtp_exit
        rtcp_ch := st.rtcp_exit
        ws_ch := st.ws_exit
        last_stats := map[webrtc.SSRC]stats.InboundRTPStreamStats{}
        for {
            select {
            case <-*rtp_ch:
                pc.Close()
                ldebug(st.cid, "close peerconnection, rtp_exit")
                return
            case <- *rtcp_ch:
                pc.Close()
                ldebug(st.cid, "close peerconnection, rtcp_exit")
            case <- *ws_ch:
                pc.Close()
                ldebug(st.cid, "close peerconnection, ws_exit")
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

func on_event(cfg *AppCfg, st *RunningState, cs *ConnectStats, buf []byte) bool {
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
                go receive_streaming(cfg, st, cs, &info.orig_sdp)
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

func keep_trying(cid int, retry *int64, msg string) bool {
    lerror(cid, msg)
    if *retry == 0 {
        return false
    } else if *retry > 0 {
        linfo(cid, "Try reconnecting")
        *retry--
    }

    return true
}

func create_state(cid int, cfg *AppCfg) *RunningState {
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

    return &state
}


func sub_request(cid int, state *RunningState, cfg *AppCfg, retry *int64, sub_url string) (bool, *SubscribeResp) {
        // we now send json request to the subscribe url
        var reqJson = ReqJson{StreamAccountId: cfg.streamAccountId, StreamName: cfg.streamName}
        bs, err := json.Marshal(&reqJson)
        if err != nil {
            log.Fatal("Failed to marshal json data: ", err)
        }

        client := &http.Client{}
        var sub *SubscribeResp
        req, err := http.NewRequest("POST", sub_url, bytes.NewBuffer(bs))
        if err != nil {
            if !keep_trying(cid, retry, "") {
                return false, nil
            } else {
                return true, nil
            }
        }
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
            if !keep_trying(cid, retry, "Failed to decode json returned from server") {
                return false, nil
            } else {
                return true, nil
            }
        }
        return true, sub
}

func generate_jwt_token(payload string, appKey string) string {
    const h string = "{\"type\":\"JWT\",\"alg\":\"HS256\"}"
    header := url_friendly(strings.TrimRight(b64.StdEncoding.EncodeToString([]byte(h)), "="))
    encoded_payload := url_friendly(strings.TrimRight(b64.StdEncoding.EncodeToString([]byte(payload)), "="))
    jwt := header + "." + encoded_payload
    signature := url_friendly(strings.TrimRight(hmac_sha256(jwt, appKey), "="))
    return jwt + "." + signature
}


func rtcbackup_request(st *RunningState, url string, token *string) *string {
    // send rtcbackup post request with the token
    req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(st.local_sdp)))
    if err != nil {
        lerror(st.cid, "Failed to create HTTP post object: ", err);
        return nil
    }
    req.Header.Add("Authorization", "Bearer " + *token)
    req.Header.Set("Content-Type", "application/sdp")
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        linfo(st.cid, fmt.Sprintf("Failed to post offer sdp to %v, err: %v", url, err))
        return nil
    }
    body, err := ioutil.ReadAll(resp.Body)
    answer := string(body)
    if resp.StatusCode != 201 {
        linfo(st.cid, "Server returned status code:", resp.StatusCode, ", error: ", answer)
        return nil
    }
    return &answer
}

func connect(wg *sync.WaitGroup, cid int, cfg *AppCfg, retry int64) {
    if cfg.rtcbackup {
        go connect_rtcbackup(wg, cid, cfg, retry)
    } else {
        go connect_ws(wg, cid, cfg, retry)
    }
}

func connect_rtcbackup(wg *sync.WaitGroup, cid int, cfg *AppCfg, retry int64) {
    defer wg.Done()
    state := create_state(cid, cfg)

    // try to get the permissio to do connecting if needed
    if cfg.rate_limit_connecting != nil {
        <-*cfg.rate_limit_connecting
        state.connecting.Store(true)
        defer func() {
            b := state.connecting.Load()
            if b {
                state.connecting.Store(false)
                *cfg.rate_limit_connecting <- struct{}{}
            }
        }()
    }

    const rtcbackup_url_tpl string = "https://director%v.millicast.com/api/rtcbackup/sub/%v/%v"

    rtc_url := fmt.Sprintf(rtcbackup_url_tpl, *cfg.rtcbackup_cfg.platform, cfg.rtcbackup_cfg.appId, cfg.streamName)

    for {
        var cs ConnectStats
        cs.UserID = state.LocalUser
        cs.TestName = *cfg.test_name

        token := generate_jwt_token(generate_rtcbackup_payload(cfg.rtcbackup_cfg.appId, cfg.streamName), cfg.rtcbackup_cfg.appKey)

        now := time.Now()
        answer := rtcbackup_request(state, rtc_url, &token)
        if answer == nil {
            if !keep_trying(cid, &retry, fmt.Sprintf("Failed to POST offer sdp")) {
                return
            } else {
                continue
            }
        }
        cs.HttpSubscribe = (float64(time.Since(now)))/1000000.0


        _ws_exit := make(chan struct{})
        _rtp_exit := make(chan struct{})
        _rtcp_exit := make(chan struct{})
        state.ws_exit = &_ws_exit
        state.rtp_exit = &_rtp_exit
        state.rtcp_exit = &_rtcp_exit

        go receive_streaming(cfg, state, &cs, answer)

        select {
        case <- _rtp_exit:
            break
        case <- _rtcp_exit:
            break
        }

        close(_ws_exit)
        if retry == 0 {
            break
        } else if retry < 0 {
            // If retry is negative, it will retry forever
        } else {
            linfo(cid, "Connection is recreated!")
            retry--
        }
    }
}



func connect_ws(wg *sync.WaitGroup, cid int, cfg *AppCfg, retry int64) {
    defer wg.Done()

    state := create_state(cid, cfg)

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

    const subscribe_url_tpl string = "https://director%v.millicast.com/api/director/subscribe"
    sub_url := fmt.Sprintf(subscribe_url_tpl, get_domain_suffix(cfg.viewer_url))


    for {
        var cs ConnectStats
        cs.UserID = state.LocalUser
        cs.TestName = *cfg.test_name
        now := time.Now()
        ok, sub := sub_request(cid, state, cfg, &retry, sub_url)
        if !ok {
            break
        } else if sub == nil {
            continue
        }

        wss_url, err := url.Parse(sub.Url + "?token=" + sub.Jwt)

        if err != nil {
            if !keep_trying(cid, &retry, fmt.Sprintf("The wss url seems to be invalid: %v", err)) {
                return
            } else {
                continue
            }
        }

        // we've successfully got wss address, we know http subscribe time
        cs.HttpSubscribe = (float64(time.Since(now)))/1000000.0

        // we now visit wss url
        conn, _, err := websocket.DefaultDialer.Dial(wss_url.String(), nil)
        if err != nil {
            if !keep_trying(cid, &retry, fmt.Sprintf("Failed to connect websocket url: %v", wss_url.String())) {
                return
            } else {
                continue
            }
        }

        // prepare json
        _events := []string{"active", "inactive", "layers", "viewercount"}
        var sdp_mp = map[string]interface{}{"sdp": state.local_sdp, "streamId": cfg.streamName, "events": _events}
        var cmd = TransCommand{Type: "cmd", TransId: 0, Name: "view", Data: sdp_mp}
        bs, err := json.Marshal(&cmd)
        if err != nil {
            if !keep_trying(cid, &retry, fmt.Sprintf("Failed to marshal json data: %v", err)) {
                return
            } else {
                continue
            }
        }

        // Send view command
        err = conn.WriteMessage(websocket.TextMessage, bs)
        if err != nil {
            if !keep_trying(cid, &retry, fmt.Sprintf("Failed to send sdp via websocket connection: %v", err)) {
                return
            } else {
                continue
            }
        }

        _ws_exit := make(chan struct{})
        _rtp_exit := make(chan struct{})
        _rtcp_exit := make(chan struct{})
        state.ws_exit = &_ws_exit
        state.rtp_exit = &_rtp_exit
        state.rtcp_exit = &_rtcp_exit
        loop_ch := make(chan struct{})

        go func() {
            for {
                t, buf, err := conn.ReadMessage()
                if err != nil {
                    lerror(cid, "Failed to read message from websocket: ", err)
                    conn.Close()
                    linfo(cid, "Connection task exit due to websocket error")
                    break
                }
                if t == websocket.TextMessage {
                    if !on_event(cfg, state, &cs, buf) {
                        conn.Close()
                        linfo(cid, "Connection task exit")
                        break
                    }
                } else {
                    // we recieved binary
                    ldebug(cid, "Received binary data message")
                }
            }
            close(loop_ch)
        }()

        select {
        case <- loop_ch:
            break
        case <- _rtp_exit:
            break
        case <- _rtcp_exit:
            break
        }
        close(_ws_exit)

        if retry == 0 {
            break
        } else if retry < 0 {
            // If retry is negative, it will retry forever
        } else {
            linfo(cid, "Connection is recreated!")
            retry--
        }
    }
}
