package counter

import (
	"strconv"
	"sync/atomic"
	"time"

	"github.com/dustin/go-humanize"
	logger "github.com/sirupsen/logrus"
)

type stats struct {
	Action     string
	Expected   uint64
	Actual     uint64
	Percentage int
}

func (c *Counter) statsByAction(n string) *stats {
	stats := &stats{
		Action: n,
	}
	if s, ok := c.list[n]; ok {
		stats.Expected, stats.Actual = atomic.LoadUint64(&s.expected), atomic.LoadUint64(&s.actual)
	}

	if stats.Expected > 0 {
		stats.Percentage = int(100 * stats.Actual / stats.Expected)
	}

	return stats
}

func (c *Counter) globalStats() (stats map[string]interface{}) {
	stats = make(map[string]interface{})
	if c.proc != nil {
		delta := time.Now().Sub(c.lastT)
		s, _ := c.proc.NewStat()
		stats["cpu"] = strconv.FormatFloat((s.CPUTime()-c.lastS.CPUTime())/delta.Seconds()*100, 'f', 1, 64) + "%"
		stats["res_mem"] = humanize.Bytes(uint64(s.ResidentMemory()))
		stats["virt_mem"] = humanize.Bytes(uint64(s.VirtualMemory()))
		c.lastS = &s
	}

	stats["sleep"] = time.Duration(c.sleep)
	stats["throughput"] = strconv.FormatFloat(float64(c.i)/c.tickD.Seconds(), 'f', 1, 64) + " EPS"
	return
}

func (c *Counter) logStats() {
	c.log.Info("collecting...")
	stats := c.globalStats()
	logStatsEntry := c.log.WithFields(logger.Fields(stats))

	time.Sleep(time.Second)
	for _, n := range c.actions {
		s := c.statsByAction(n)
		logEntry := c.log.WithField("expected", s.Expected).WithField("actual", s.Actual)
		logEntry.Infof("%s (%d%% lost)", s.Action, 100-s.Percentage)
	}
	logStatsEntry.Info("statistics")
}
