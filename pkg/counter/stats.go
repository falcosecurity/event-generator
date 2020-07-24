package counter

import (
	"strconv"
	"time"

	"github.com/dustin/go-humanize"
	logger "github.com/sirupsen/logrus"
)

type Stats struct {
	Action     string
	Expected   uint64
	Actual     uint64
	Percentage int
}

func (c *Counter) logStats() {
	if c.proc != nil {
		ps := c.procStats()
		c.log.WithFields(logger.Fields(ps)).Info("proc stats")
	}
	for _, n := range c.actions {
		s := c.Stats(n)
		logEntry := c.log.WithField("expected", s.Expected).WithField("actual", s.Actual)
		logEntry.Infof("%s (%d%% lost)", s.Action, 100-s.Percentage)
	}
}

func (c *Counter) procStats() (stats map[string]interface{}) {
	stats = make(map[string]interface{})
	if c.proc != nil {
		delta := time.Now().Sub(c.lastT)
		s, _ := c.proc.NewStat()
		stats["cpu"] = strconv.FormatFloat((s.CPUTime()-c.lastS.CPUTime())/delta.Seconds()*100, 'f', 1, 64) + "%"
		stats["res_mem"] = humanize.Bytes(uint64(s.ResidentMemory()))
		stats["virt_mem"] = humanize.Bytes(uint64(s.VirtualMemory()))
		c.lastS = &s
	}
	return
}

func (c *Counter) Stats(n string) *Stats {
	stats := &Stats{
		Action: n,
	}
	stats.Expected, stats.Actual = c.statsByAction(n)

	if stats.Expected > 0 {
		stats.Percentage = int(100 * stats.Actual / stats.Expected)
	}

	return stats
}
