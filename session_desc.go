package main

import (
	"math/rand"
	"strconv"
	"strings"
	log "github.com/sirupsen/logrus"

	"github.com/pion/sdp/v2"
	"github.com/pion/webrtc/v3"
)


type ICEInfo struct {
    Ufrag string
    Pwd string
    Lite bool
    EndOfCandidate bool
}


type DTLSInfo struct {
    Hash string
    Fingerprint string
    Setup string
}


type trackDetails struct {
	mid        string
	kind       webrtc.RTPCodecType
	streamID   string
	id         string
	ssrcs      []webrtc.SSRC
	repairSsrc *webrtc.SSRC
	rids       []string
}


type AnswerSDPInfo struct {
    Ice ICEInfo
    Dtls DTLSInfo 
    Candidates []string    
    RTPRecvParams webrtc.RTPReceiveParameters
}

// SDP from real use case, use it as a template and make some change
const sdp_string = "v=0\r\no=- 2233441212137801125 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0 1\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS\r\nm=video 9 UDP/TLS/RTP/SAVPF 96 97 98 99 100 101 35 36 37 38 102 123 127 122 125 107 108 109 124 121 39 40 41 42 43 44 45 46 47 48 120 119 114 49\r\nc=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\na=ice-ufrag:mvU1\r\na=ice-pwd:s48zvtqqEq4TE3a41iOHj3Ik\r\na=ice-options:trickle\r\na=fingerprint:sha-256 90:F8:17:AC:AF:8D:17:0C:3A:60:28:61:74:1B:A0:C1:22:30:95:B5:03:ED:79:22:2B:2A:97:C3:FF:8B:82:F4\r\na=setup:actpass\r\na=mid:0\r\na=extmap:12 http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time\r\na=extmap:1 urn:ietf:params:rtp-hdrext:toffset\r\na=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\na=extmap:3 urn:3gpp:video-orientation\r\na=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\na=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\na=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type\r\na=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing\r\na=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space\r\na=extmap:9 urn:ietf:params:rtp-hdrext:sdes:mid\r\na=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\na=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\na=recvonly\r\na=rtcp-mux\r\na=rtcp-rsize\r\na=rtpmap:96 VP8/90000\r\na=rtcp-fb:96 goog-remb\r\na=rtcp-fb:96 transport-cc\r\na=rtcp-fb:96 ccm fir\r\na=rtcp-fb:96 nack\r\na=rtcp-fb:96 nack pli\r\na=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=96\r\na=rtpmap:98 VP9/90000\r\na=rtcp-fb:98 goog-remb\r\na=rtcp-fb:98 transport-cc\r\na=rtcp-fb:98 ccm fir\r\na=rtcp-fb:98 nack\r\na=rtcp-fb:98 nack pli\r\na=fmtp:98 profile-id=0\r\na=rtpmap:99 rtx/90000\r\na=fmtp:99 apt=98\r\na=rtpmap:100 VP9/90000\r\na=rtcp-fb:100 goog-remb\r\na=rtcp-fb:100 transport-cc\r\na=rtcp-fb:100 ccm fir\r\na=rtcp-fb:100 nack\r\na=rtcp-fb:100 nack pli\r\na=fmtp:100 profile-id=2\r\na=rtpmap:101 rtx/90000\r\na=fmtp:101 apt=100\r\na=rtpmap:35 VP9/90000\r\na=rtcp-fb:35 goog-remb\r\na=rtcp-fb:35 transport-cc\r\na=rtcp-fb:35 ccm fir\r\na=rtcp-fb:35 nack\r\na=rtcp-fb:35 nack pli\r\na=fmtp:35 profile-id=1\r\na=rtpmap:36 rtx/90000\r\na=fmtp:36 apt=35\r\na=rtpmap:37 VP9/90000\r\na=rtcp-fb:37 goog-remb\r\na=rtcp-fb:37 transport-cc\r\na=rtcp-fb:37 ccm fir\r\na=rtcp-fb:37 nack\r\na=rtcp-fb:37 nack pli\r\na=fmtp:37 profile-id=3\r\na=rtpmap:38 rtx/90000\r\na=fmtp:38 apt=37\r\na=rtpmap:102 H264/90000\r\na=rtcp-fb:102 goog-remb\r\na=rtcp-fb:102 transport-cc\r\na=rtcp-fb:102 ccm fir\r\na=rtcp-fb:102 nack\r\na=rtcp-fb:102 nack pli\r\na=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\na=rtpmap:123 rtx/90000\r\na=fmtp:123 apt=102\r\na=rtpmap:127 H264/90000\r\na=rtcp-fb:127 goog-remb\r\na=rtcp-fb:127 transport-cc\r\na=rtcp-fb:127 ccm fir\r\na=rtcp-fb:127 nack\r\na=rtcp-fb:127 nack pli\r\na=fmtp:127 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f\r\na=rtpmap:122 rtx/90000\r\na=fmtp:122 apt=127\r\na=rtpmap:125 H264/90000\r\na=rtcp-fb:125 goog-remb\r\na=rtcp-fb:125 transport-cc\r\na=rtcp-fb:125 ccm fir\r\na=rtcp-fb:125 nack\r\na=rtcp-fb:125 nack pli\r\na=fmtp:125 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\na=rtpmap:107 rtx/90000\r\na=fmtp:107 apt=125\r\na=rtpmap:108 H264/90000\r\na=rtcp-fb:108 goog-remb\r\na=rtcp-fb:108 transport-cc\r\na=rtcp-fb:108 ccm fir\r\na=rtcp-fb:108 nack\r\na=rtcp-fb:108 nack pli\r\na=fmtp:108 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f\r\na=rtpmap:109 rtx/90000\r\na=fmtp:109 apt=108\r\na=rtpmap:124 H264/90000\r\na=rtcp-fb:124 goog-remb\r\na=rtcp-fb:124 transport-cc\r\na=rtcp-fb:124 ccm fir\r\na=rtcp-fb:124 nack\r\na=rtcp-fb:124 nack pli\r\na=fmtp:124 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=4d001f\r\na=rtpmap:121 rtx/90000\r\na=fmtp:121 apt=124\r\na=rtpmap:39 H264/90000\r\na=rtcp-fb:39 goog-remb\r\na=rtcp-fb:39 transport-cc\r\na=rtcp-fb:39 ccm fir\r\na=rtcp-fb:39 nack\r\na=rtcp-fb:39 nack pli\r\na=fmtp:39 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=4d001f\r\na=rtpmap:40 rtx/90000\r\na=fmtp:40 apt=39\r\na=rtpmap:41 H264/90000\r\na=rtcp-fb:41 goog-remb\r\na=rtcp-fb:41 transport-cc\r\na=rtcp-fb:41 ccm fir\r\na=rtcp-fb:41 nack\r\na=rtcp-fb:41 nack pli\r\na=fmtp:41 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=f4001f\r\na=rtpmap:42 rtx/90000\r\na=fmtp:42 apt=41\r\na=rtpmap:43 H264/90000\r\na=rtcp-fb:43 goog-remb\r\na=rtcp-fb:43 transport-cc\r\na=rtcp-fb:43 ccm fir\r\na=rtcp-fb:43 nack\r\na=rtcp-fb:43 nack pli\r\na=fmtp:43 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=f4001f\r\na=rtpmap:44 rtx/90000\r\na=fmtp:44 apt=43\r\na=rtpmap:45 AV1/90000\r\na=rtcp-fb:45 goog-remb\r\na=rtcp-fb:45 transport-cc\r\na=rtcp-fb:45 ccm fir\r\na=rtcp-fb:45 nack\r\na=rtcp-fb:45 nack pli\r\na=rtpmap:46 rtx/90000\r\na=fmtp:46 apt=45\r\na=rtpmap:47 AV1/90000\r\na=rtcp-fb:47 goog-remb\r\na=rtcp-fb:47 transport-cc\r\na=rtcp-fb:47 ccm fir\r\na=rtcp-fb:47 nack\r\na=rtcp-fb:47 nack pli\r\na=fmtp:47 profile=1\r\na=rtpmap:48 rtx/90000\r\na=fmtp:48 apt=47\r\na=rtpmap:120 red/90000\r\na=rtpmap:119 rtx/90000\r\na=fmtp:119 apt=120\r\na=rtpmap:114 ulpfec/90000\r\na=rtpmap:49 flexfec-03/90000\r\na=rtcp-fb:49 goog-remb\r\na=rtcp-fb:49 transport-cc\r\na=fmtp:49 repair-window=10000000\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111 63 103 104 9 0 8 106 105 13 110 112 113 126 115\r\na=rtpmap:115 multiopus/48000/6\r\na=fmtp:115 channel_mapping=0,4,1,2,3,5;coupled_streams=2;minptime=10;num_streams=4;useinbandfec=1\r\nc=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\na=ice-ufrag:mvU1\r\na=ice-pwd:s48zvtqqEq4TE3a41iOHj3Ik\r\na=ice-options:trickle\r\na=fingerprint:sha-256 90:F8:17:AC:AF:8D:17:0C:3A:60:28:61:74:1B:A0:C1:22:30:95:B5:03:ED:79:22:2B:2A:97:C3:FF:8B:82:F4\r\na=setup:actpass\r\na=mid:1\r\na=extmap:12 http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time\r\na=extmap:14 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\na=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\na=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\na=extmap:9 urn:ietf:params:rtp-hdrext:sdes:mid\r\na=recvonly\r\na=rtcp-mux\r\na=rtpmap:111 opus/48000/2\r\na=rtcp-fb:111 transport-cc\r\na=fmtp:111 minptime=10;useinbandfec=1; stereo=1\r\na=rtpmap:63 red/48000/2\r\na=fmtp:63 111/111\r\na=rtpmap:103 ISAC/16000\r\na=rtpmap:104 ISAC/32000\r\na=rtpmap:9 G722/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:106 CN/32000\r\na=rtpmap:105 CN/16000\r\na=rtpmap:13 CN/8000\r\na=rtpmap:110 telephone-event/48000\r\na=rtpmap:112 telephone-event/32000\r\na=rtpmap:113 telephone-event/16000\r\na=rtpmap:126 telephone-event/8000\r\n"


func checkICE(info *ICEInfo) *ICEInfo {
    if info.Ufrag == "" || info.Pwd == "" {
        return nil
    }
    return info
}

func checkDTLS(info *DTLSInfo) *DTLSInfo {
    if info.Hash == "" || info.Fingerprint == "" || info.Setup == "" {
        return nil
    }
    return info
}

func checkAnswerSDP(info *AnswerSDPInfo) *AnswerSDPInfo {
    if checkICE(&info.Ice) == nil || checkDTLS(&info.Dtls) == nil || len(info.Candidates) == 0 {
        return nil
    } 
    return info
}


func genRandomHash(length uint) string {
    return genRandomString(length, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}


func genRandomString(length uint, chars string) string {
    var lens = len(chars)
    res := ""
    for i := uint(0); i < length; i++ {
        res += string(chars[rand.Intn(lens)])
    }
    return res
}


func createReqSDP(user string, pwd string, hash string, fingerprint string) string {
    sd := sdp.SessionDescription{}
    sd.Unmarshal([]byte(sdp_string))

    sd.Origin.SessionID = rand.Uint64() 

    // replace original values
    for _, m := range sd.MediaDescriptions {
        for i, a := range m.Attributes {
            if a.Key == "ice-ufrag" {
                m.Attributes[i].Value = user
            } else if a.Key == "ice-pwd" {
                m.Attributes[i].Value = pwd
            } else if a.Key == "fingerprint" {
                m.Attributes[i].Value = hash + " " + fingerprint
            } 
        }
    }
    
    b, err := sd.Marshal()
    if err != nil {
        log.Fatal("Failed to generate SDP: ", err)
    }
    return string(b)
}


func filterTrackWithSSRC(incomingTracks []trackDetails, ssrc webrtc.SSRC) []trackDetails {
	filtered := []trackDetails{}
	doesTrackHaveSSRC := func(t trackDetails) bool {
		for i := range t.ssrcs {
			if t.ssrcs[i] == ssrc {
				return true
			}
		}

		return false
	}

	for i := range incomingTracks {
		if !doesTrackHaveSSRC(incomingTracks[i]) {
			filtered = append(filtered, incomingTracks[i])
		}
	}

	return filtered
}


func readAnswerSDP(answer string) *AnswerSDPInfo {
    sd := sdp.SessionDescription{}
    sd.Unmarshal([]byte(answer))

    var info = AnswerSDPInfo{}


    // global attributes
    for _, a := range sd.Attributes {
        if a.Key == "ice-lite" {
            info.Ice.Lite = true
        } else if a.Key == "end-of-candidates" {
            info.Ice.EndOfCandidate = true
        }
    }

    for _, m := range sd.MediaDescriptions {
        // skip recvonly and inactive
		if _, ok := m.Attribute(sdp.AttrKeyRecvOnly); ok {
			continue
		} else if _, ok := m.Attribute(sdp.AttrKeyInactive); ok {
			continue
		}
        tracksInMediaSection := []trackDetails{}
        rtxRepairFlows := map[uint64]uint64{}
        streamID := ""
        trackID := ""
        midValue := "" 
        rids := map[string]string{}
        codecType := webrtc.NewRTPCodecType(m.MediaName.Media)
        for _, a := range m.Attributes {
            if a.Key == "ice-ufrag" {
                info.Ice.Ufrag = a.Value
            } else if a.Key == "ice-pwd" {
                info.Ice.Pwd = a.Value
            } else if a.Key == "fingerprint" {
                sp := strings.Split(a.Value, " ")
                info.Dtls.Hash = sp[0]
                // accoridng to some comment in pion code, it should be lowercased
                // dtlsfingerprint.go
                info.Dtls.Fingerprint = strings.ToLower(sp[1])
            } else if a.Key == "setup" {
                info.Dtls.Setup = a.Value
            } else if a.IsICECandidate() {
                info.Candidates = append(info.Candidates, *a.String())
            } else if a.Key == sdp.AttrKeyMID {
                midValue = a.Value
            } else if a.Key == "rid" {
                split := strings.Split(a.Value, " ")
                rids[split[0]] = a.Value

            } else if a.Key == "ssrc-group" {
                split := strings.Split(a.Value, " ")
                if split[0] == sdp.SemanticTokenFlowIdentification {
                    if len(split) == 3 {
                        baseSSRC, err := strconv.ParseUint(split[1], 10, 32)
                        if err != nil {
                            log.Warn("Failed to parse SSRC: v%", err)
                            continue
                        }
                        rtxRepairFlow, err := strconv.ParseUint(split[2], 10, 32)
                        if err != nil {
                            log.Warn("Failed to parse SSRC: %v", err)
                            continue
                        }
                        rtxRepairFlows[rtxRepairFlow] = baseSSRC
                        tracksInMediaSection = filterTrackWithSSRC(tracksInMediaSection, webrtc.SSRC(rtxRepairFlow))
                    }
                }
            } else if a.Key == sdp.AttrKeyMsid {
                split := strings.Split(a.Value, " ")
                if len(split) == 2 {
                    streamID = split[0]
                    trackID = split[1]
                }
            } else if a.Key == sdp.AttrKeySSRC {
                split := strings.Split(a.Value, " ")
                ssrc, err := strconv.ParseUint(split[0], 10, 32)
                if err != nil {
                    log.Warn("Failed to parse SSRC: %v", err)
                    continue
                }
                if _, ok := rtxRepairFlows[ssrc]; ok {
                    continue
                }
                if len(split) == 3 && strings.HasPrefix(split[1], "msid:") {
                    streamID = split[1][len("msid:"):]
                    trackID = split[2]
                }
                newTrack := true
                td := &trackDetails{}
                for i := range tracksInMediaSection {
                    for j:= range tracksInMediaSection[i].ssrcs {
                        if tracksInMediaSection[i].ssrcs[j] == webrtc.SSRC(ssrc) {
                            td = &tracksInMediaSection[i]
                            newTrack = false
                        }
                    }
                }
                td.mid = midValue
                td.ssrcs = []webrtc.SSRC{webrtc.SSRC(ssrc)}
                td.id = trackID
                td.kind = codecType
                td.streamID = streamID
                for r, baseSSRC := range rtxRepairFlows {
                    if baseSSRC == ssrc {
                        repairSsrc := webrtc.SSRC(r)
                        td.repairSsrc = &repairSsrc
                    }
                }
                if newTrack {
                    tracksInMediaSection = append(tracksInMediaSection, *td)
                }
            } 
        }
        if len(rids) != 0 && trackID != "" && streamID != "" {
            simulcastTrack := trackDetails {
                mid: midValue,
                kind: codecType,
                streamID: streamID,
                id: trackID,
                rids: []string{},
            }
            for rid := range rids {
                simulcastTrack.rids = append(simulcastTrack.rids, rid)
            }
            tracksInMediaSection = []trackDetails{simulcastTrack}
        }
       //  for t := range tracksInMediaSection {
       //      for r := range tracksInMediaSection[t].rids {
       //          info.RTPRecvParams.Encodings = append(info.RTPRecvParams.Encodings, webrtc.RTPDecodingParameters{
       //              webrtc.RTPCodingParameters{RID:r, SSRC:tracksInMediaSection[t].
       //          })
       //      }
       // }
    }
    
    return checkAnswerSDP(&info)
}

