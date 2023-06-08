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
    "strconv"
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
    "github.com/pion/interceptor"
    "github.com/pion/interceptor/pkg/stats"
    "github.com/pion/logging"
    "github.com/pion/webrtc/v3"

	"github.com/pion/webrtc/v3/pkg/media"

    log "github.com/sirupsen/logrus"
)

const MAX_RTP_LEN = 2000

type SubReqJson struct {
    StreamAccountId string `json:"streamAccountId"`
    StreamName      string `json:"streamName"`
}

type PubReqJson struct {
    StreamName    string `json:"streamName"`
    StreamType    string `json:"streamType"`
}

type PubSubResp struct {
    Url              string
    Jwt              string
    StreamAccountId  string
    IceServers       []webrtc.ICEServer
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
    Resp       *PubSubResp        // publish/subscribe response
    pc         *webrtc.PeerConnection
    g          *stats.Getter
    offer      *webrtc.SessionDescription
    server     string             // the media server addr
    connecting atomic.Bool
    conn_exit  chan struct{}
    conn_ch    chan bool         // this is to notify stats goroutine the state of connection
    close_conn func()
}

type ConnectStats struct {
    UserID string                `json:"userId"`
    Server string                `json:"server"`
    TestName string              `json:"TestName"`
    HttpPubSub float64           `json:"httpSubscribe"`
    ICESetup float64             `json:"iceSetup"`
    DTLSSetup float64            `json:"dtlsSetup"`
    FirstRTP float64             `json:"firstRTP"`
    TotalTime float64            `json:"totalTime"`
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


func addIceServer(o interface{}, sub *PubSubResp) {
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

func check_resp_result(result map[string]interface{}) *PubSubResp {
    var resp PubSubResp
    if status, ok := result["status"]; !ok || status != "success" {
        log.Error("The response status is not 'success', it is ", status)
        return nil
    }

    if d, ok := result["data"]; ok {
        data := d.(map[string]interface{})

        if j, ok := data["jwt"]; ok {
            resp.Jwt = j.(string)
        } else {
            log.Error("Found no jwt in json")
            return nil
        }
        if u, ok := data["wsUrl"]; ok {
            resp.Url = u.(string)
        } else {
            log.Error("Found no wsUrl in json")
            return nil
        }
        if s, ok := data["streamAccountId"]; ok {
            resp.StreamAccountId = s.(string)
        }

        if m, ok := data["iceServers"]; ok {
            mm := m.([]interface{})
            for _, i := range mm {
                addIceServer(i, &resp)
            }
        } else {
            log.Debug("Found no ice servers in json")
        }
    }

    return &resp
}



func create_peerconnection(cfg *AppCfg, st *RunningState) (*webrtc.PeerConnection, *stats.Getter) {
    var err error
    m := &webrtc.MediaEngine{}

    rtcpFeedback := []webrtc.RTCPFeedback{
        {Type: "goog-remb", Parameter: ""},
        {Type: "ccm", Parameter: "fir"},
        {Type: "transport-cc", Parameter: ""},
    }

    if !cfg.nack_off {
        rtcpFeedback = append(rtcpFeedback, webrtc.RTCPFeedback{Type: "nack", Parameter: ""})
        rtcpFeedback = append(rtcpFeedback, webrtc.RTCPFeedback{Type: "nack", Parameter: "pli"})
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
            RTCPFeedback: rtcpFeedback},
            PayloadType: webrtc.PayloadType(payload_type)}, webrtc.RTPCodecTypeVideo)
    if err != nil {
        panic(err)
    }

    err = m.RegisterCodec(
        webrtc.RTPCodecParameters{
            RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000,
            Channels: 0, RTCPFeedback:rtcpFeedback},
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
    if err := webrtc.ConfigureRTCPReports(ic); err != nil {
        panic(err)
    }
    if err := webrtc.ConfigureTWCCSender(m, ic); err != nil {
        panic(err)
    }
    if !cfg.nack_off {
        if err := webrtc.ConfigureNack(m, ic); err != nil {
            panic(err)
        }
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

    return pc, &g
}

func stats_read(cfg *AppCfg, st *RunningState) {
    last_stats := map[webrtc.SSRC]stats.InboundRTPStreamStats{}
    pc := st.pc
    g := st.g
    var connected bool
    var skip bool
    for {
        select {
        case <- st.conn_exit:
            pc.Close()
            ldebug(st.LocalUser, "pc.Close() called, stats report goroutine exit, notified by conn_exit")
            return
        case conn_state := <- st.conn_ch:
            if connected && !conn_state {
                // we are now disconnected, so the last stats data is discarded 
                last_stats = make(map[webrtc.SSRC]stats.InboundRTPStreamStats)
                ldebug(st.LocalUser, "stats report goroutine paused, notified by conn_ch")
            }  else if !connected && conn_state {
                ldebug(st.LocalUser, "stats report goroutine continued, notified by conn_ch")
            }
            connected = conn_state
        case <-time.After(time.Second * time.Duration(stats_report_interval)):
            skip = false
            if !connected {
                continue
            }
            ts := pc.GetTransceivers()
            rpt := fmt.Sprintf("{\"userId\":\"%v\"", st.LocalUser)
            rpt += fmt.Sprintf(", \"server\":\"%v\"", st.server)
            rpt += fmt.Sprintf(", \"TestName\":\"%v\"", *cfg.test_name)
            rpt += fmt.Sprintf(", \"ICE_State\":\"%v\"", pc.ICEConnectionState().String())
            rpt += fmt.Sprintf(", \"Conn_State\":\"%v\"", pc.ConnectionState().String())
            videos := []string{}
            audios := []string{}
            // remote := ""
            for _, t := range ts {
                if t == nil || t.Receiver() == nil {
                    continue
                }
                tk := t.Receiver().Track()
                if tk == nil {
                    continue
                }
                ssrc := tk.SSRC()
                o := fmt.Sprintf("{\"SSRC\":%v", ssrc)
                o += fmt.Sprintf(", \"Type\":\"%v\"", tk.Kind().String())
                r := (*g).Get(uint32(ssrc))
                if r != nil {
                    o += fmt.Sprintf(", \"PacketReceived\":%v", r.InboundRTPStreamStats.PacketsReceived)
                    o += fmt.Sprintf(", \"PacketLost\":%v", r.InboundRTPStreamStats.PacketsLost)
                    o += fmt.Sprintf(", \"Jitter(inbound)\":%v", r.InboundRTPStreamStats.Jitter)
                    o += fmt.Sprintf(", \"LastPacketReceivedTimestamp\":%f", float64(r.InboundRTPStreamStats.LastPacketReceivedTimestamp.UnixNano())/1000000000.0)
                    o += fmt.Sprintf(", \"HeaderBytesReceived\":%v", r.InboundRTPStreamStats.HeaderBytesReceived)
                    o += fmt.Sprintf(", \"BytesReceived\":%v", r.InboundRTPStreamStats.BytesReceived)
                    o += fmt.Sprintf(", \"NACKCount(inbound)\":%v", r.InboundRTPStreamStats.NACKCount)
                    o += fmt.Sprintf(", \"PLICount(inbound)\":%v", r.InboundRTPStreamStats.PLICount)
                    o += fmt.Sprintf(", \"FIRCount(inbound)\":%v", r.InboundRTPStreamStats.FIRCount)

                    o += fmt.Sprintf(", \"PacketSent\":%v", r.OutboundRTPStreamStats.PacketsSent)
                    o += fmt.Sprintf(", \"BytesSent\":%v", r.OutboundRTPStreamStats.BytesSent)
                    o += fmt.Sprintf(", \"HeaderBytesSent\":%v", r.OutboundRTPStreamStats.HeaderBytesSent)
                    o += fmt.Sprintf(", \"NACKCount(outbound)\":%v", r.OutboundRTPStreamStats.NACKCount)
                    o += fmt.Sprintf(", \"PLICount(outbound)\":%v", r.OutboundRTPStreamStats.PLICount)
                    o += fmt.Sprintf(", \"FIRCount(outbound)\":%v", r.OutboundRTPStreamStats.FIRCount)
                    last, ok := last_stats[ssrc]
                    packets_loss_percentage := float64(0)
                    bitrate := float64(0)
                    if ok {
                        packets_lost := float64(r.InboundRTPStreamStats.PacketsLost - last.PacketsLost)
                        if packets_lost < 0 {
                            packets_lost = 0
                        }
                        packets_received := float64(r.InboundRTPStreamStats.PacketsReceived - last.PacketsReceived)
                        if packets_received < 0 {
                            packets_received = 0
                        }
                        if packets_received != 0 {
                            packets_loss_percentage = 100.0 * packets_lost / packets_received
                        } else {
                            packets_loss_percentage = 0.0
                        }
                        if packets_loss_percentage > 100.0 {
                            // sometimes it happens, the lost packets is a little bit bigger than received packets
                            packets_loss_percentage = 100.0
                        }
                        bytes_received := float64(r.InboundRTPStreamStats.BytesReceived - last.BytesReceived)
                        if bytes_received < 0 {
                            bytes_received = 0
                        }
                        time_diff := float64(r.InboundRTPStreamStats.LastPacketReceivedTimestamp.Sub(last.LastPacketReceivedTimestamp).Seconds())
                        if time_diff > 0 {
                            bitrate = (8 * bytes_received / time_diff) / 1024.0
                        } else {
                            bitrate = 0.0
                        }
                    } else {
                        skip = true
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
                // if remote == "" {
                //     remote += "{"
                //     if r != nil {
                //         remote += fmt.Sprintf("\"BytesSent\":%v", r.RemoteOutboundRTPStreamStats.BytesSent)
                //         remote += fmt.Sprintf(", \"PacketsSent\":%v", r.RemoteOutboundRTPStreamStats.PacketsSent)
                //         remote += fmt.Sprintf(", \"ReportsSent\":%v", r.RemoteOutboundRTPStreamStats.ReportsSent)
                //         remote += fmt.Sprintf(", \"RoundTripTime\":\"%v\"", r.RemoteOutboundRTPStreamStats.RoundTripTime)
                //         remote += fmt.Sprintf(", \"RemoteTimeStamp\":%f", float64(r.RemoteOutboundRTPStreamStats.RemoteTimeStamp.UnixNano())/1000000000.0)
                //         remote += fmt.Sprintf(", \"TotalRoundTripTime\":\"%v\"", r.RemoteOutboundRTPStreamStats.TotalRoundTripTime)
                //         remote += fmt.Sprintf(", \"RoundTripTimeMeasurements\":%v", r.RemoteOutboundRTPStreamStats.RoundTripTimeMeasurements)
                //     }
                //     remote += "}"
                // }
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
            // rpt += fmt.Sprintf(", \"RemoteOutboundRTPStreamStats\":%v", remote)
            rpt += "}\n"
            if !skip {
                *cfg.stats_ch <- []byte(rpt)
            }
        }
    }
}

func prepare_pc_for_publishing(cfg *AppCfg, st *RunningState, cs *ConnectStats) {
    pc := st.pc

    var video_codec string
    if *cfg.codec == "h264" {
        video_codec = webrtc.MimeTypeH264
    } else if *cfg.codec == "vp8" {
        video_codec = webrtc.MimeTypeVP8
    } else if *cfg.codec == "vp9" {
        video_codec = webrtc.MimeTypeVP9
    } else {
        log.Fatal("Unknown codec type")
    }

    videoTrack, videoTrackErr := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType:video_codec}, "video", "pion")
    if videoTrackErr != nil {
        panic(videoTrackErr)
    }

    videoRtpSender, videoTrackErr := pc.AddTrack(videoTrack)
    if videoTrackErr != nil {
        panic(videoTrackErr)
    }

    audioTrack, audioTrackErr := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType:webrtc.MimeTypeOpus}, "audio", "pion")
    if audioTrackErr != nil {
        panic(audioTrackErr)
    }

    audioRtpSender, audioTrackErr := pc.AddTrack(audioTrack)
    if audioTrackErr != nil {
        panic(audioTrackErr)
    }

    iceConnected, iceConnectedCancel := context.WithCancel(context.Background())

    rtcp_read_goroutine := func(sender *webrtc.RTPSender) {
        rtcpBuf := make([]byte, 1500)
        for {
            if _, _, err := sender.Read(rtcpBuf); err != nil {
                return
            }
        }
    }

    // read rtcp pkts
    go rtcp_read_goroutine(videoRtpSender)

    // try to sync between audio and video
    // whoever finishes first, shall wait for the other one to be done
    video_done := make(chan bool, 1)
    audio_done := make(chan bool, 1)

    // send rtp pkts
    go func() {
        <- iceConnected.Done()

        ticker := time.NewTicker(cfg.streaming_video.Interval)
        // we loop forever
        var idx uint64
        var total_frames uint64 = uint64(len(cfg.streaming_video.Frames))
        for {
            select {
            case <- ticker.C:
                frame := cfg.streaming_video.Frames[idx]
                if ivfErr := videoTrack.WriteSample(media.Sample{Data:frame, Duration:time.Second}); ivfErr != nil {
                    linfo(st.LocalUser, "Failed to send video rtp: ", ivfErr)
                    st.close_conn()
                    close(video_done)
                    return
                }
                idx = (idx + 1) % total_frames
                // we are back at start point
                if idx == 0 {
                    ticker.Stop()
                    video_done <- true
                    <- audio_done
                    ticker.Reset(cfg.streaming_video.Interval)
                }
            case <- st.conn_exit:
                return
            }
        }
    }()

    go rtcp_read_goroutine(audioRtpSender)

    go func() {
        <- iceConnected.Done()

        var lastGranu uint64
        ticker := time.NewTicker(OggPageDuration)
        // we loop forever
        var idx uint64
        var total_frames uint64 = uint64(len(cfg.streaming_audio))
        for {
            select {
            case <- ticker.C:
                f := cfg.streaming_audio[idx]
                sampleCount := float64(f.granu - lastGranu)
                lastGranu = f.granu
                sampleDuration := time.Duration((sampleCount/48000)*1000) * time.Millisecond
                if oggErr := audioTrack.WriteSample(media.Sample{Data:f.frame, Duration:sampleDuration}); oggErr != nil {
                    linfo(st.LocalUser, "Failed to send audio rtp: ", oggErr)
                    st.close_conn()
                    close(audio_done)
                    return
                }
                idx = (idx + 1) % total_frames
                // we are back at start point
                if idx == 0 {
                    ticker.Stop()
                    audio_done <- true
                    <- video_done
                    ticker.Reset(OggPageDuration)
                    lastGranu = 0
                }
            case <- st.conn_exit:
                return
            }
        }
    }()

    pc.OnICEConnectionStateChange(func(connectionState webrtc.ICEConnectionState){
        linfo(st.LocalUser, "ice connection state changed to ", connectionState)
        if connectionState == webrtc.ICEConnectionStateConnected {
            iceConnectedCancel()
        }
    })

    pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState){
        ldebug(st.LocalUser, "streaming peer connection state changed to", s)
        if s == webrtc.PeerConnectionStateFailed {
            pc.Close()
            lerror(st.LocalUser, "pc.Closed() called, peer connection switched to failed")
        } else if s == webrtc.PeerConnectionStateConnected {
            // We've connected, no way we still don't know the address of remote server
            p, e := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
            if e != nil {
                lerror(st.LocalUser, "Cannot extract remote server address!")
                log.Fatal()
            }
            cs.Server = p.Remote.Address
            st.server = p.Remote.Address
            linfo(st.LocalUser, "Connected to server:", cs.Server)
        }
    })
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
    pc, offer := st.pc, st.offer

    var ice_state webrtc.ICEConnectionState = webrtc.ICEConnectionStateNew
    var conn_state webrtc.PeerConnectionState = webrtc.PeerConnectionStateNew

    iceStart := time.Now()
    dtlsStart := iceStart
    firstRTP := dtlsStart
    iceConnected := false
    dtlsConnected := false
    firstRTPReceived := false
    pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
        linfo(st.LocalUser, "ice connection state changed to ", state)
        ice_state = state
        if ice_state == webrtc.ICEConnectionStateFailed {
            pc.Close()
            lerror(st.LocalUser, "ice connection failed, pc.Closed() called")
            st.close_conn()
        }
        if (!iceConnected && ice_state == webrtc.ICEConnectionStateConnected) {
            iceConnected = true
            cs.ICESetup = (float64(time.Since(iceStart)))/1000000.0
            dtlsStart = time.Now()
        }
    })


    pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
        ldebug(st.LocalUser, "connection state switched to ", state)

        if conn_state == webrtc.PeerConnectionStateConnected && state != webrtc.PeerConnectionStateConnected {
            st.conn_ch <- false
        }
        if conn_state != webrtc.PeerConnectionStateConnected && state == webrtc.PeerConnectionStateConnected {
            st.conn_ch <- true
        }

        conn_state = state
        if conn_state == webrtc.PeerConnectionStateFailed {
            pc.Close()
            lerror(st.LocalUser, "connection failed, pc.Closed() called")
            st.close_conn()
        }
        if state == webrtc.PeerConnectionStateConnected {
            // We've connected, no way we still don't know the address of remote server
            p, e := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
            if e != nil {
                lerror(st.LocalUser, "Cannot extract remote server address!")
                log.Fatal()
            }
            cs.Server = p.Remote.Address
            st.server = p.Remote.Address
            linfo(st.LocalUser, "Connected to server:", cs.Server)

            if (!dtlsConnected && iceConnected) {
                dtlsConnected = true;
                cs.DTLSSetup = (float64(time.Since(dtlsStart)))/1000000.0
                firstRTP = time.Now()
            }
        }
    })

    pc.OnTrack(func(tr *webrtc.TrackRemote, rc *webrtc.RTPReceiver) {
        go func() {
            rtp_buf := make([]byte, MAX_RTP_LEN)
            for {
                _, _, err := tr.Read(rtp_buf)
                if err != nil {
                    break
                }
                if (!firstRTPReceived) {
                    firstRTPReceived = true
                    cs.FirstRTP = (float64(time.Since(firstRTP)))/1000000.0
                    cs.TotalTime = (float64(time.Since(iceStart)))/1000000.0
                    // we'll send the connect stats now
                    bs, err := json.Marshal(cs)
                    if err == nil {
                        bs = append(bs, byte('\n'))
                        *cfg.stats_ch <- bs
                    }
                }
            }
            pc.Close()
            ldebug(st.LocalUser, fmt.Sprintf("RTP read goroutine for %v: %v exit, pc.Closed() called", tr.Kind().String(), tr.SSRC()))
            st.close_conn()
        }()

        go func() {
            rtcp_buf := make([]byte, MAX_RTP_LEN)
            for {
                _, _, err := rc.Read(rtcp_buf)
                if err != nil {
                    break
                }
            }
            pc.Close()
            ldebug(st.LocalUser, fmt.Sprintf("RTCP read goroutine for %v: %v exit, pc.Closed() called", rc.Track().Kind().String(), rc.Track().SSRC()))
            st.close_conn()
        }()
    })

    if err = pc.SetLocalDescription(*offer); err != nil {
        panic(err)
    }

    remote := webrtc.SessionDescription{SDP: *answer_sdp, Type: webrtc.SDPTypeAnswer}
    if err = pc.SetRemoteDescription(remote); err != nil {
        panic(err)
    }

    go stats_read(cfg, st)
}


func on_event(cfg *AppCfg, st *RunningState, cs *ConnectStats, buf []byte) bool {
    var ev map[string]interface{}
    err := json.Unmarshal(buf, &ev)
    if err != nil {
        // even though we received some weird json, we are staying
        lerror(st.LocalUser, "Failed to unmarshal received json: ", string(buf))
        return true
    }

    var answer_sdp string
    if e, ok := ev["type"]; !ok {
        lerror(st.LocalUser, "Unrecognized json: ", string(buf))
    } else {
        if e == "response" {
            if data, ok := ev["data"]; !ok {
                lerror(st.LocalUser, "Found no data in the response json: ", string(buf))
                return false
            } else {
                if answer_sdp == "" {
                    m := data.(map[string]interface{})
                    answer_sdp = m["sdp"].(string)
                    if cfg.streaming {
                        linfo(st.LocalUser, "clusterId =", m["clusterId"], "streamId =", m["streamId"], "publisherId =", m["publisherId"])
                    } else {
                        linfo(st.LocalUser, "clusterId =", m["clusterId"], "streamViewId =", m["streamViewId"], "subscriberId =", m["subscriberId"])
                    }
                }
                if cfg.streaming {
                    send_streaming(cfg, st, &answer_sdp)
                } else {
                    receive_streaming(cfg, st, cs, &answer_sdp)
                }
            }
        } else {
            if n, ok := ev["name"]; !ok {
                lerror(st.LocalUser, "No name for this event: ", string(buf))
            } else {
                if n == "stopped" {
                    linfo(st.LocalUser, fmt.Sprintf("Server stopped streaming: %v", string(buf)))
                    return false
                } else if n == "inactive" {
                    // This means the server temporarily pauses streaming
                    // but as long as the DTLS connection is still alive, we do not need to do anything
                    // because when server starts streaming again,  DTLS conn will just work
                    // linfo(st.LocalUser, "Server is inactive")
                    // if wait_on_inactive is true, we'll stay
                    ldebug(st.LocalUser, "Server is inactive")
                    return cfg.wait_on_inactive
                } else if n == "active" {
                    /// This means the server continues streaming
                    // linfo(st.LocalUser, "Server is active")
                } else {
                    // ldebug(st.LocalUser, "Received ws message: ", string(buf))
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

func keep_trying(user *string, retry *int64, msg string) bool {
    lerror(user, msg)
    if *retry == 0 {
        return false
    } else if *retry > 0 {
        linfo(user, "Try reconnecting")
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

    var state = RunningState{cid: cid, Cert: *cert, LocalUser: genRandomHash(16), LocalPwd: genRandomHash(48)}
    ldebug(state.LocalUser, " Ready for connection.")

    return &state
}


func pubsub_request(cid int, state *RunningState, cfg *AppCfg, retry *int64, url string) (bool, time.Time, *PubSubResp, *string) {
    var bs []byte
    if cfg.streaming {
        var reqJson = PubReqJson{StreamName:cfg.streamName, StreamType:"WebRtc"}
        _bs, err := json.Marshal(&reqJson)
        if err != nil {
            log.Fatal("Failed to marshal json data: ", err)
        }
        bs = _bs
    } else {
        var reqJson = SubReqJson{StreamAccountId: cfg.streamAccountId, StreamName: cfg.streamName}
        _bs, err := json.Marshal(&reqJson)
        if err != nil {
            log.Fatal("Failed to marshal json data: ", err)
        }
        bs = _bs
    }

    var parsed_resp *PubSubResp

    // This is second, even it is a time.Duration type, dont forget to multiply time.Second
    var delay time.Duration = 0 
    var now time.Time
    var attempt int = 0
    var x_req_id string
    for {
        if delay > 0 {
            time.Sleep(delay * time.Second)
        }
        client := &http.Client{}
        req, err := http.NewRequest("POST", url, bytes.NewBuffer(bs))
        if err != nil {
            lerror(state.LocalUser, "Failed to create http request object, err: ", err)
            log.Fatal()
        }

        req.Header.Set("Content-Type", "application/json")
        if cfg.streaming {
            req.Header.Add("Authorization", "Bearer " + *cfg.ptoken)
        }
        now = time.Now()
        resp, err := client.Do(req)
        if err != nil {
            // This should not happen
            lerror(state.LocalUser, "Failed to post request json to url: ", url, ",  err: ", err)
            log.Fatal()
        }

        if resp.StatusCode == 200 || resp.StatusCode == 201 {
            body, err := ioutil.ReadAll(resp.Body)
            if err != nil {
                lerror(state.LocalUser, "Failed to read data from response, err: ", err)
                log.Fatal()
            }

            var result map[string]interface{}
            err = json.Unmarshal(body, &result)
            if err != nil {
                lerror(state.LocalUser, "Failed to unmarshal returned response json: ", string(body))
                log.Fatal()
            }

            parsed_resp = check_resp_result(result)
            if parsed_resp == nil {
                lerror(state.LocalUser, "Server returned a success status code, but the json is not valid")
                log.Fatal()
            } else {
                state.Resp = parsed_resp
            }

            if _id, ok := resp.Header["X-Request-id"]; ok {
                x_req_id = _id[0]
            }
            break
        }

        if resp.StatusCode < 400 || resp.StatusCode > 499 {
            lerror(state.LocalUser, "Server return status code", resp.StatusCode, ", connect goroutine exits")
            return false, now, nil, &x_req_id
        } else if resp.StatusCode == 401 {
            lerror(state.LocalUser, "Received Unauthorized 401 status code from server, connect goroutine exits")
            return false, now, nil, &x_req_id
        } else {
            attempt += 1
            body, err := ioutil.ReadAll(resp.Body)
            if err != nil {
                lerror(state.LocalUser, "Failed to read body: ", err)
                log.Fatal()
            }
            if resp.StatusCode == 429 {
                retry_after, ok := resp.Header["Retry-After"]
                if ok {
                    _delay, err := strconv.Atoi(retry_after[0])
                    if err == nil && _delay > 0 {
                        delay = time.Duration(_delay)
                        linfo(state.LocalUser, "Server is on rate limit, will try reconnecting after", delay * time.Second, "as per server's request. Body:'", string(body), "'. Attempt: ", attempt)
                        continue
                    } 
                }
                linfo(state.LocalUser, "Server returns 429 status code without 'Retry-After' field or with an invalid 'Retry-After' field in the HTTP header. Body:", string(body))
            }

            if delay == 0 {
                delay = 1
            } else {
                delay = 2 * delay 
            }
            if delay > 64 {
                delay = 64
            }
            linfo(state.LocalUser, "Server's status code:", resp.StatusCode, ". Wait", delay * time.Second, "and retry. Body:'", string(body), "'. Attemp: ", attempt)
        } 
    }
    return true, now, parsed_resp, &x_req_id
}

func generate_jwt_token(payload string, appKey string) string {
    const h string = "{\"type\":\"JWT\",\"alg\":\"HS256\"}"
    header := url_friendly(strings.TrimRight(b64.StdEncoding.EncodeToString([]byte(h)), "="))
    encoded_payload := url_friendly(strings.TrimRight(b64.StdEncoding.EncodeToString([]byte(payload)), "="))
    jwt := header + "." + encoded_payload
    signature := url_friendly(strings.TrimRight(hmac_sha256(jwt, appKey), "="))
    return jwt + "." + signature
}


func rtcbackup_request(state *RunningState, url string, cfg *AppCfg, postfix *string) (*string, time.Time, *string) {
    var now time.Time
    var answer string
    var delay time.Duration
    var attempt int
    var x_req_id string

    action := "sub"
    if cfg.streaming {
        action = "pub"
    }

    for {
        if delay > 0 {
            time.Sleep(delay * time.Second)
        }

        var token string
        if cfg.streaming  {
            token = generate_jwt_token(generate_rtcbackup_payload(cfg.appId, action, cfg.streamName + *postfix), cfg.appKey)
        }

        req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(state.offer.SDP)))
        if err != nil {
            lerror(state.LocalUser, "Failed to create HTTP post object: ", err);
            log.Fatal()
            return nil, now, &x_req_id
        }
        if cfg.streaming {
            req.Header.Add("Authorization", "Bearer " + token)
        }
        req.Header.Set("Content-Type", "application/sdp")

        client := &http.Client{}

        now = time.Now()
        resp, err := client.Do(req)
        if err != nil {
            lerror(state.LocalUser, fmt.Sprintf("Failed to post offer sdp to %v, err: %v", url, err))
            log.Fatal()
            return nil, now, &x_req_id
        }

        if resp.StatusCode == 200 || resp.StatusCode == 201 {
            body, err := ioutil.ReadAll(resp.Body)
            if err != nil {
                lerror(state.LocalUser, "Failed to read from response body")
                log.Fatal()
            }
            answer = string(body)
            if _id, ok := resp.Header["X-Request-id"]; ok {
                x_req_id = _id[0]
            }
            break
        }

        if resp.StatusCode < 400 || resp.StatusCode > 499 {
            lerror(state.LocalUser, "Server return status code", resp.StatusCode, ", connect goroutine exits")
            return nil, now, &x_req_id
        } else if resp.StatusCode == 401 {
            lerror(state.LocalUser, "Received Unauthorized 401 status code from server, connect goroutine exits")
            return nil, now, &x_req_id
        } else {
            attempt += 1
            body, err := ioutil.ReadAll(resp.Body)
            if err != nil {
                lerror(state.LocalUser, "Failed to read body: ", err)
                log.Fatal()
            }
            if resp.StatusCode == 429 {
                retry_after, ok := resp.Header["Retry-After"]
                if ok {
                    _delay, err := strconv.Atoi(retry_after[0])
                    if err == nil && _delay > 0 {
                        delay = time.Duration(_delay)
                        ldebug(state.LocalUser, "Server is on rate limit, will try reconnecting after", delay * time.Second, "as per server's request. Body:'", string(body), "'. Attempt: ", attempt)
                        continue
                    } 
                }
                ldebug(state.LocalUser, "Server returns 429 status code wihout 'Retry-After' field or with an invalid 'Retry-After' field in the HTTP header. Body:", string(body))
            }

            if delay == 0 {
                delay = 1
            } else {
                delay = 2 * delay 
            }
            if delay > 64 {
                delay = 64
            }
            ldebug(state.LocalUser, "Server's status code:", resp.StatusCode, ". Wait", delay * time.Second, "and retry. Body:'", string(body), "'. Attemp: ", attempt)
        }
    }
    return &answer, now, &x_req_id
}

func send_streaming(cfg *AppCfg, st *RunningState, answer_sdp *string) {
    err := st.pc.SetLocalDescription(*st.offer)
    if err != nil {
       panic(err)
    }
    remote := webrtc.SessionDescription{SDP: *answer_sdp, Type: webrtc.SDPTypeAnswer}
    st.pc.SetRemoteDescription(remote)
    // go stats_read(cfg, st)
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

    const rtcbackup_view_tpl string = "https://director%v.millicast.com/api/rtcbackup/sub/%v/%v"
    const rtcbackup_stream_tpl string ="https://director%v.millicast.com/api/rtcbackup/pub/%v/%v?Vcodec=%v"

    postfix := ""
    if cid > 0 {
        postfix = strconv.Itoa(cid)
    }
    var rtc_url string = fmt.Sprintf(rtcbackup_view_tpl, *cfg.platform, cfg.appId, cfg.streamName)
    if cfg.streaming {
        rtc_url = fmt.Sprintf(rtcbackup_stream_tpl, *cfg.platform, cfg.appId, cfg.streamName + postfix, *cfg.codec)
    } else if cfg.one_on_one {
        rtc_url = fmt.Sprintf(rtcbackup_view_tpl, *cfg.platform, cfg.appId, cfg.streamName + postfix)
    }

    for {
        var cs ConnectStats
        cs.UserID = state.LocalUser
        cs.TestName = *cfg.test_name

        state.pc, state.g = create_peerconnection(cfg, state)

        if !cfg.streaming {
            _, err := state.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly})
            if err != nil {
                panic(err)
            }
            _, err = state.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly})
            if err != nil {
                panic(err)
            }
        } else {
            prepare_pc_for_publishing(cfg, state, &cs)
        }

        offer, err := state.pc.CreateOffer(nil)
        if err != nil {
            panic(err)
        }
        state.offer = &offer
        answer, now, x_req_id := rtcbackup_request(state, rtc_url, cfg, &postfix)
        if answer == nil {
            if !keep_trying(&state.LocalUser, &retry, fmt.Sprintf("Failed to POST offer sdp")) {
                return
            } else {
                continue
            }
        }
        httpSpentTime := time.Since(now)
        if httpSpentTime > time.Second {
            linfo(state.LocalUser, "See long http subscribe time (>1s) with X-Request-id:", *x_req_id)
        }
        cs.HttpPubSub = (float64(httpSpentTime))/1000000.0

        state.conn_ch = make(chan bool)
        state.conn_exit = make(chan struct{})
        var cc sync.Once
        state.close_conn = func() {
            cc.Do(func(){
                close(state.conn_exit)
            })
        }

        if cfg.streaming {
            send_streaming(cfg, state, answer)
        } else {
            receive_streaming(cfg, state, &cs, answer)
        }

        <-state.conn_exit
        state.pc.Close()
        ldebug(state.LocalUser, "PeerConnection is completely closed")
        if retry == 0 {
            break
        } else if retry < 0 {
            // If retry is negative, it will retry forever
        } else {
            linfo(state.LocalUser, "Connection is recreated!")
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
    const publish_url_tpl string = "https://director%v.millicast.com/api/director/publish"
    var target_url string

    if cfg.streaming {
        target_url = fmt.Sprintf(publish_url_tpl, *cfg.platform) 
    } else {
        target_url = fmt.Sprintf(subscribe_url_tpl, *cfg.platform)
    }


    for {
        var cs ConnectStats
        cs.UserID = state.LocalUser
        cs.TestName = *cfg.test_name
        ok, now, resp, x_req_id := pubsub_request(cid, state, cfg, &retry, target_url)
        if !ok {
            break
        } 

        wss_url, err := url.Parse(resp.Url + "?token=" + resp.Jwt)
        if err != nil {
            lerror(state.LocalUser, "The wss url seems to be invalid: ", err)
            return
        }

        // we've successfully got wss address, we know http publish/subscribe time

        httpSpentTime := time.Since(now)
        if httpSpentTime > time.Second {
            linfo(state.LocalUser, "See long http subscribe time (>1s) with X-Request-id:", *x_req_id)
        }
        cs.HttpPubSub = (float64(httpSpentTime))/1000000.0

        // we now visit wss url
        conn, _, err := websocket.DefaultDialer.Dial(wss_url.String(), nil)
        if err != nil {
            lerror(state.LocalUser, "Failed to connect websocket url: ", wss_url)
            return
        }

        // Until now, we find out the stream account id, now we can generate the view url for convenience
        if cfg.streaming && !printed_view_url {
            check_url_tpl := "https://viewer%v.millicast.com?streamId=%v/%v"
            check_url := fmt.Sprintf(check_url_tpl, *cfg.platform, resp.StreamAccountId, cfg.streamName)
            fmt.Println("\n---------------------------------------------------------------")
            fmt.Println("View URL:")
            fmt.Println(check_url)
            fmt.Println()
            fmt.Print("---------------------------------------------------------------\n\n")
            printed_view_url = true
        }

        state.pc, state.g = create_peerconnection(cfg, state)


        var cmd TransCommand
        if cfg.streaming {
            prepare_pc_for_publishing(cfg, state, &cs)
        } else {
            _, err = state.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly})
            if err != nil {
                panic(err)
            }
            _, err = state.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly})
            if err != nil {
                panic(err)
            }
        }

        offer, err := state.pc.CreateOffer(nil)
        if err != nil {
            panic(err)
        }
        state.offer = &offer

        if cfg.streaming {
            _events := []string{"viewercount"}
            var sdp_mp = map[string]interface{}{"sdp": offer.SDP, "name": cfg.streamName, "codec": cfg.codec, "record": false, "events": _events}
            cmd = TransCommand{Type: "cmd", TransId: 0, Name: "publish", Data: sdp_mp}

        } else {
            _events := []string{"active", "inactive", "layers", "viewercount"}
            var sdp_mp = map[string]interface{}{"sdp": offer.SDP, "streamId": cfg.streamName, "events": _events}

            cmd = TransCommand{Type: "cmd", TransId: 0, Name: "view", Data: sdp_mp}
        }

        bs, err := json.Marshal(&cmd)
        if err != nil {
            lerror(state.LocalUser, "Failed to marshal json data: ", err)
            return
        }


        // Send command
        err = conn.WriteMessage(websocket.TextMessage, bs)
        if err != nil {
            lerror(state.LocalUser, "Failed to send sdp via websocket connection: ", err)
            return
        }


        state.conn_ch = make(chan bool)
        state.conn_exit = make(chan struct{})
        var cc sync.Once
        state.close_conn = func() {
            cc.Do(func(){
                close(state.conn_exit)
            })
        }

        go func() {
            for {
                t, buf, err := conn.ReadMessage()
                if err != nil {
                    lerror(state.LocalUser, "Failed to read message from websocket: ", err)
                    conn.Close()
                    linfo(state.LocalUser, "Connection task exit due to websocket error")
                    break
                }
                if t == websocket.TextMessage {
                    if !on_event(cfg, state, &cs, buf) {
                        conn.Close()
                        linfo(state.LocalUser, "Connection task exit")
                        break
                    }
                } else {
                    // we recieved binary
                    ldebug(state.LocalUser, "Received binary data message")
                }
            }
            state.close_conn()
        }()

        <-state.conn_exit

        ldebug(state.LocalUser, "Connection is completely closed")

        if retry == 0 {
            break
        } else if retry < 0 {
            // If retry is negative, it will retry forever
        } else {
            linfo(state.LocalUser, "Connection is recreated!")
            retry--
        }
    }
}
