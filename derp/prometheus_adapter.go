package derp

import (
	"io"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

var (
	expFormat = expfmt.NewFormat(expfmt.TypeTextPlain)
)

// collectorVar implements expvar.Var and metrics.PrometheusWriter
type collectorVar struct {
	prometheus.Collector
}

func (cw collectorVar) String() string {
	return `"CollectorVar"`
}

func (cw collectorVar) WritePrometheus(w io.Writer, name string) {
	reg := prometheus.NewRegistry()
	_ = reg.Register(cw)
	mfs, _ := reg.Gather()
	enc := expfmt.NewEncoder(w, expFormat)
	for _, mf := range mfs {
		_ = enc.Encode(mf)
	}
}
