package cmd

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	dnsQueryCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "cloud_native_app",
			Subsystem: "backend",
			Name:      "http_requests_total",
			Help:      "Number of HTTP requests",
		},
		[]string{"type", "query"},
	)
)
