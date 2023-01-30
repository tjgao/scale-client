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

    // "crypto/x509"
    "encoding/json"
    "io/ioutil"

    // "net"
    "errors"
    "net/http"
    "net/url"
    "regexp"

    "github.com/gorilla/websocket"
    "github.com/pion/ice/v2"
    "github.com/pion/webrtc/v3"

    log "github.com/sirupsen/logrus"
)

type ReqJson struct {
    StreamAccountId string `json:"streamAccountId"`
    StreamName      string `json:"streamName"`
}

type IceServer struct {
    Urls       []string
    Username   string
    Credential string
}

type SubscribeResp struct {
    Url        string
    Jwt        string
    IceServers []IceServer
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
    cid       int                // an integer to identifiy a connection
    Cert      webrtc.Certificate // local cert
    LocalUser string             // ice user
    LocalPwd  string             // ice pwd
    SubResp   SubscribeResp      // subscribe response
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

const subscribe_url string = "https://director.millicast.com/api/director/subscribe"

// parse the url to get stream account id and name
func parse(url string) map[string]string {
    re := regexp.MustCompile("http.+streamId=(?P<streamAccountId>[0-9a-z]+)/(?P<streamName>[0-9a-z]+)")
    r := re.FindAllStringSubmatch(url, -1)[0]
    keys := re.SubexpNames()
    md := map[string]string{}
    for i, n := range r {
        md[keys[i]] = n
    }
    return md
}

func addIceServer(o interface{}, sub *SubscribeResp) {
    var ice IceServer
    m := o.(map[string]interface{})
    if u, ok := m["urls"]; ok {
        _u := u.([]interface{})
        for _, uu := range _u {
            ice.Urls = append(ice.Urls, uu.(string))
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

func receive_rtp_streaming(st *RunningState, info *AnswerSDPInfo) {
    // prepare ICE gathering options
    iceOptions := webrtc.ICEGatherOptions{}
    for _, is := range st.SubResp.IceServers {
        iceOptions.ICEServers = append(iceOptions.ICEServers,
            webrtc.ICEServer{URLs: is.Urls, Username: is.Username, Credential: is.Credential})
    }

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

func receive_streaming(st *RunningState, info *AnswerSDPInfo) {
    receive_rtp_streaming(st, info)
    // c := create_ice_connection(st, info)
    // if c != nil {
    //     log.Debug("ICE connection is created!")
    // }

    // port, err := strconv.Atoi(info.remotePort)
    // if err != nil {
    //     log.Error("Found no valid port in Answer SDP")
    //     return
    // }
    // addr := &net.UDPAddr{IP: net.ParseIP(info.remoteIp), Port: port}
    // config := &dtls.Config {
    //     Certificates: []tls.Certificate{st.cert},
    //     InsecureSkipVerify: true,
    //     ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
    // }
    // ctx, cancel := context.WithTimeout(context.Background(), 10 * time.Second)
    // defer cancel()
    // dtlsConn, err := dtls.DialWithContext(ctx, "udp", addr, config)
    // if err != nil {
    //     log.Error("Failed to create DTLS connection: ", err)
    //     return
    // }
    //
    // st.StreamingStarted = true
    // b := make([]byte, 10240)
    // for {
    //     n, err := dtlsConn.Read(b)
    //     if err != nil {
    //         log.Error("Failed to receive data from dtls connection: ", err)
    //         break
    //     }
    //     log.Debug("Read a packet with size ", n, " from dtls connection!")
    // }
    // st.StreamingStarted = false
}

func on_event(st *RunningState, ev map[string]interface{}, buf []byte) bool {
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
                go receive_streaming(st, info)
            }
        } else {
            if n, ok := ev["name"]; !ok {
                lerror(st.cid, "No name for this event: ", string(buf))
            } else {
                if n == "stopped" {
                    linfo(st.cid, "Server stopped streaming")
                    return false
                } else if n == "inactive" {
                    // This means the server temporarily pauses streaming
                    // but as long as the DTLS connection is still alive, we do not need to do anything
                    // because when server starts streaming again,  DTLS conn will just work
                    linfo(st.cid, "Server is inactive")
                } else if n == "active" {
                    /// This means the server continues streaming
                    linfo(st.cid, "Server is active")
                } else {
                    ldebug(st.cid, "Received ws message: ", string(buf))
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

func connect(cid int, wg *sync.WaitGroup, access_url string) {
    defer wg.Done()
    m := parse(access_url)
    if _, ok := m["streamAccountId"]; !ok {
        log.Fatal("Failed to extract streamAccountId from URL: ", access_url)
    }
    if _, ok := m["streamName"]; !ok {
        log.Fatal("Failed to extract streamName from URL: ", access_url)
    }

    client := &http.Client{}
    resp, err := client.Get(access_url)
    if err != nil {
        log.Fatal("Failed to access url: ", err)
    }

    resp.Body.Close()

    streamName := m["streamName"]
    // we now send json request to the subscribe url
    var reqJson = ReqJson{StreamAccountId: m["streamAccountId"], StreamName: m["streamName"]}
    bs, err := json.Marshal(&reqJson)
    if err != nil {
        log.Fatal("Failed to marshal json data: ", err)
    }

    req, err := http.NewRequest("POST", subscribe_url, bytes.NewBuffer(bs))
    req.Header.Set("Content-Type", "application/json")
    resp, err = client.Do(req)
    if err != nil {
        log.Fatal("Failed to post request json to url: ", subscribe_url, ",  err: ", err)
    }

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Fatal("Failed to read data from response, err: ", err)
    }

    var result map[string]interface{}
    err = json.Unmarshal(body, &result)
    if err != nil {
        log.Fatal("Failed to unmarshal returned response json: ", body)
    }

    sub := check_result(result)
    if sub == nil {
        log.Fatal("Server's response is not valid")
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

    var state = RunningState{cid, *cert, genRandomHash(16), genRandomHash(48), *sub}

    req_sdp := createReqSDP(state.LocalUser, state.LocalPwd, "sha-256", fingerprint[0].Value)

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

    // Now wait for response and other events
    for {
        t, buf, err := conn.ReadMessage()
        if err != nil {
            lerror(cid, "Failed to read message from websocket: ", err)
            break
        }
        if t == websocket.TextMessage {
            // we received text message, treat it as json
            var result map[string]interface{}
            err = json.Unmarshal(buf, &result)
            if err != nil {
                lerror(cid, "Failed to unmarshal received json: ", string(buf))
            } else {
                if !on_event(&state, result, buf) {
                    linfo(cid, "Connection task exit")
                    break
                }
            }
        } else {
            // we recieved binary
            ldebug(cid, "Received binary data message")
        }
    }
}
