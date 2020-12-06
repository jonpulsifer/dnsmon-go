package main

import (
	"flag"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

func init() {
	// set default log level
	log.SetLevel(log.InfoLevel)
	// register dnsCounter metric
	prometheus.MustRegister(dnsCounter)
}

func main() {
	var (
		iface   string
		promisc bool
		snaplen int
		verbose bool
	)

	// cli flags
	flag.StringVar(&iface, "interface", "", "interface to listen on")
	flag.BoolVar(&promisc, "promisc", true, "promiscuous mode")
	flag.BoolVar(&verbose, "verbose", false, "enable debug logging")
	flag.IntVar(&snaplen, "snaplen", 65536, "packet snap length")
	flag.Parse()

	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	if len(flag.Args()) == 0 {
		log.WithFields(log.Fields{
			"promiscuous": promisc,
			"snaplen":     snaplen,
		}).Info("No flags specified, using defaults")
	}

	switch strings.ToLower(iface) {
	case "", "any", "all":
		// find network interfaces
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		// get the first device with an IP address
		for _, device := range devices {
			if len(device.Addresses) > 0 {
				handle, err := pcap.OpenLive(device.Name, int32(snaplen), promisc, pcap.BlockForever)
				if err != nil {
					log.Fatal(err)
				}
				defer handle.Close()
				log.Infof("Listening on device: %s", device.Name)
				go listenToInterface(handle)
			}
		}
	default:
		handle, err := pcap.OpenLive(iface, int32(snaplen), promisc, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
		log.Infof("Listening on device: %s", iface)
		listenToInterface(handle)
	}
}

func listenToInterface(handle *pcap.Handle) {
	// packet vars
	var (
		eth layers.Ethernet
		ip4 layers.IPv4
		ip6 layers.IPv6
		dst string
		src string
		tcp layers.TCP
		udp layers.UDP
		dns layers.DNS
	)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns)
	decodedLayers := []gopacket.LayerType{}

	packets := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packets.Packets() {
		parser.DecodeLayers(packet.Data(), &decodedLayers)
		// start dns logger
		dnsLog := log.WithFields(log.Fields{})

		// iterate through decoded packets
		for _, layerType := range decodedLayers {
			switch layerType {
			case layers.LayerTypeIPv4:
				src = ip4.SrcIP.String()
				dst = ip4.DstIP.String()
				dnsLog = dnsLog.WithFields(log.Fields{"src": src, "dst": dst})
			case layers.LayerTypeIPv6:
				src = ip6.DstIP.String()
				dst = ip6.DstIP.String()
				dnsLog = dnsLog.WithFields(log.Fields{"src": src, "dst": dst})
			case layers.LayerTypeDNS:
				dnsLog = dnsLog.WithFields(log.Fields{
					"opcode": dns.OpCode.String(),
					"rcode":  dns.ResponseCode.String(),
					"id":     uint16(dns.ID),
				})
				for _, query := range dns.Questions {
					// type, class, opcode, rcode
					dnsCounter.WithLabelValues(query.Type.String(), query.Class.String(), dns.OpCode.String(), dns.ResponseCode.String()).Inc()
					dnsLog.WithFields(log.Fields{
						"class": query.Class.String(),
						"name":  string(query.Name),
						"type":  query.Type.String(),
					}).Info("QUERY")
				}
				for _, answer := range dns.Answers {
					dnsCounter.WithLabelValues(answer.Type.String(), answer.Class.String(), dns.OpCode.String(), dns.ResponseCode.String()).Inc()
					// base answer context
					dnsLog = dnsLog.WithFields(log.Fields{
						"class": answer.Class.String(),
						"name":  string(answer.Name),
						"type":  answer.Type.String(),
					})

					// iterate over types (MX, A, TXT)
					switch answer.Type.String() {
					case "A":
						dnsLog = dnsLog.WithFields(log.Fields{"ip": answer.IP.String()})
					case "AAAA":
						dnsLog = dnsLog.WithFields(log.Fields{"ip": answer.IP.String()})
					case "NS":
						dnsLog = dnsLog.WithFields(log.Fields{"nameserver": string(answer.NS)})
					case "CNAME":
						dnsLog = dnsLog.WithFields(log.Fields{"value": string(answer.CNAME)})
					case "PTR":
						dnsLog = dnsLog.WithFields(log.Fields{"value": string(answer.PTR)})
					case "SOA":
						dnsLog = dnsLog.WithFields(log.Fields{
							"mname":   string(answer.SOA.MName),
							"rname":   string(answer.SOA.RName),
							"serial":  int32(answer.SOA.Serial),
							"refresh": int32(answer.SOA.Refresh),
							"retry":   int32(answer.SOA.Retry),
							"expire":  int32(answer.SOA.Expire),
							"minimum": int32(answer.SOA.Minimum),
						})
					case "MX":
						dnsLog = dnsLog.WithFields(log.Fields{
							"name":       string(answer.MX.Name),
							"preference": int16(answer.MX.Preference),
						})
					case "TXT":
						var txts []string
						for _, txt := range answer.TXTs {
							txts = append(txts, string(txt))
						}
						dnsLog = dnsLog.WithFields(log.Fields{"txt": strings.Join(txts, " ")})
					case "SRV":
						dnsLog = dnsLog.WithFields(log.Fields{
							"priority": int16(answer.SRV.Priority),
							"weight":   int16(answer.SRV.Weight),
							"port":     int16(answer.SRV.Port),
							"name":     string(answer.SRV.Name),
						})
					}
					dnsLog.Info("ANSWER")
				}

			}
		}
	}
}
