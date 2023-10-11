// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package counter

import (
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/dustin/go-humanize"
	logger "github.com/sirupsen/logrus"
)

type stats struct {
	Action   string
	Expected uint64
	Actual   uint64
	Ratio    float64
}

func (c *Counter) statsByAction(n string) *stats {
	stats := &stats{
		Action: n,
	}
	if s, ok := c.list[n]; ok {
		stats.Expected, stats.Actual = atomic.LoadUint64(&s.expected), atomic.LoadUint64(&s.actual)
	}

	if stats.Expected > 0 {
		stats.Ratio = float64(stats.Actual) / float64(stats.Expected)
	}

	return stats
}

func (c *Counter) globalStats() (stats map[string]interface{}) {
	stats = make(map[string]interface{})
	if c.proc != nil {
		delta := time.Now().Sub(c.lastT)
		s, _ := c.proc.NewStat()
		stats["cpu"] = float64((s.CPUTime() - c.lastS.CPUTime()) / delta.Seconds())
		stats["res_mem"] = uint64(s.ResidentMemory())
		stats["virt_mem"] = uint64(s.VirtualMemory())

		if c.humanize {
			stats["cpu"] = strconv.FormatFloat(stats["cpu"].(float64)*100, 'f', 1, 64) + "%"
			stats["res_mem"] = humanize.Bytes(uint64(stats["res_mem"].(uint64)))
			stats["virt_mem"] = humanize.Bytes(stats["virt_mem"].(uint64))
		}

		c.lastS = &s

	}
	stats["throughput"] = float64(c.i) / c.tickD.Seconds()
	if c.humanize {
		stats["throughput"] = strconv.FormatFloat(stats["throughput"].(float64), 'f', 1, 64) + " EPS"
	}
	return
}

func (c *Counter) logStats() {
	stats := c.globalStats()
	logStatsEntry := c.log.WithFields(logger.Fields(stats))

	var lost float64
	for _, n := range c.actions {
		s := c.statsByAction(n)
		logEntry := c.log.WithField("expected", s.Expected).WithField("actual", s.Actual).WithField("ratio", s.Ratio)
		logEntry.Info(s.Action)
		lost += s.Ratio
	}

	if !c.dryRun {
		lost = 1 - lost/float64(len(c.actions)) // lost average
		if c.humanize {
			logStatsEntry = logStatsEntry.WithField("lost", fmt.Sprintf("%d%%", int(lost*100)))
		} else {
			logStatsEntry = logStatsEntry.WithField("lost", lost)
		}
	}

	logStatsEntry.Info("statistics")
}
