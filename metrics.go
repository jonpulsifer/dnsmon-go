package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
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

func init() {
	// set up metrics endpoint
	log.Info("Prometheus endpoint: http://0.0.0.0:8080/metrics")
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe("0.0.0.0:8080", nil)
}
