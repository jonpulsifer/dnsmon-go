package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	dnsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dns",
			Subsystem: "record",
			Name:      "counter",
			Help:      "DNS Record Total",
		},
		[]string{"type", "class", "opcode", "rcode"},
	)
)
