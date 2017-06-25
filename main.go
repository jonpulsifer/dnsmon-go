// Copyright © 2017 Jonathan Pulsifer
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package main

import (
	"flag"
	"net/http"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// RootCmd represents the base command when called without any subcommands
// var RootCmd = &cobra.Command{
// 	Use:   "dnsmon-go",
// 	Short: "Monitor network interfaces for DNS traffic and log it",
// 	Long: `
// Inspired by github.com/gamelinux/passivedns, dnsmon-go
// listens to a given network interface and logs DNS traffic.

// #patcheswelcome #cloudnative`,

func init() {
	// register dnsCounter metric
	prometheus.MustRegister(dnsCounter)
}

func main() {
	var iface string

	// cli flags
	flag.StringVar(&iface, "interface", "", "interface to listen on")
	flag.Parse()

	if iface == "" {
		log.Info("Interface not specified, enumerating devices")

		// find network interfaces
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		// get the first device with an IP address
		for _, device := range devices {
			if len(device.Addresses) > 0 {
				iface = device.Name
				break
			}
		}
	}

	// set up metrics endpoint
	log.Info("Prometheus endpoint: http://0.0.0.0:8080/metrics")
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe("0.0.0.0:8080", nil)

	// set up interface handler
	log.Infof("Listening on device: %s", iface)
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalln(err)
	}
	defer handle.Close()

	// packet vars
	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		ip6     layers.IPv6
		dst     string
		src     string
		tcp     layers.TCP
		udp     layers.UDP
		dns     layers.DNS
		payload gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)
	decodedLayers := []gopacket.LayerType{}

	packets := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packets.Packets() {
		err := parser.DecodeLayers(packet.Data(), &decodedLayers)
		// errors are only for packets we don't care about
		if err != nil {
			log.Debugln(err)
		}

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
					"id":     int16(dns.ID),
				})
				for _, query := range dns.Questions {
					// type, class, opcode, rcode
					dnsCounter.WithLabelValues(query.Type.String(), query.Class.String(), dns.OpCode.String(), dns.ResponseCode.String()).Inc()
					dnsLog = dnsLog.WithFields(log.Fields{
						"class": query.Class.String(),
						"name":  string(query.Name),
						"type":  query.Type.String(),
					})
					dnsLog.Info("QUERY")
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
						dnsLog = dnsLog.WithFields(log.Fields{"mname": string(answer.SOA.MName)})
						dnsLog = dnsLog.WithFields(log.Fields{"rname": string(answer.SOA.RName)})
						dnsLog = dnsLog.WithFields(log.Fields{"serial": int32(answer.SOA.Serial)})
						dnsLog = dnsLog.WithFields(log.Fields{"refresh": int32(answer.SOA.Refresh)})
						dnsLog = dnsLog.WithFields(log.Fields{"retry": int32(answer.SOA.Retry)})
						dnsLog = dnsLog.WithFields(log.Fields{"expire": int32(answer.SOA.Expire)})
						dnsLog = dnsLog.WithFields(log.Fields{"minimum": int32(answer.SOA.Minimum)})
					case "MX":
						dnsLog = dnsLog.WithFields(log.Fields{"name": string(answer.MX.Name)})
						dnsLog = dnsLog.WithFields(log.Fields{"preference": int16(answer.MX.Preference)})
					case "TXT":
						var txts []string
						for _, txt := range answer.TXTs {
							txts = append(txts, string(txt))
						}
						dnsLog = dnsLog.WithFields(log.Fields{"txt": strings.Join(txts, " ")})
					case "SRV":
						dnsLog = dnsLog.WithFields(log.Fields{"priority": int16(answer.SRV.Priority)})
						dnsLog = dnsLog.WithFields(log.Fields{"weight": int16(answer.SRV.Weight)})
						dnsLog = dnsLog.WithFields(log.Fields{"prort": int16(answer.SRV.Port)})
						dnsLog = dnsLog.WithFields(log.Fields{"name": string(answer.SRV.Name)})
					}
					dnsLog.Info("ANSWER")
				}

			}
		}
	}
}
