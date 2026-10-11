// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"testing"
	"time"
)

type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Debug(string, ...any) {}

func TestSilencedRuleDoesNotAct(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	var bans []string
	e := New(nopLogger{}, Deps{
		GetRepeatBanIP: func(time.Time, int) (string, int) { return "203.0.113.7", 5 },
		BanIP: func(ip, _ string, _ time.Duration) error {
			bans = append(bans, ip)
			return nil
		},
	})
	e.now = func() time.Time { return now }
	var logs []ExecLog
	e.OnRuleFired = func(l ExecLog) { logs = append(logs, l) }
	e.ReplaceRules([]Rule{{ID: "r1", Name: "récidive", Enabled: true, CooldownSec: 120,
		Condition:      Condition{Type: CondBanRepeat},
		Action:         Action{Type: ActionBanIP},
		SilenceWindows: []SilenceWindow{{Starts: now.Add(-time.Minute), Ends: now.Add(30 * time.Minute)}}}})

	e.evalAll()
	now = now.Add(30 * time.Second)
	e.evalAll()
	if len(bans) != 0 {
		t.Fatalf("action exécutée pendant la mise en sourdine : %v", bans)
	}
	if len(logs) != 1 || !logs[0].Silenced || logs[0].ActionTaken || !logs[0].CondResult || logs[0].RuleID != "r1" {
		t.Fatalf("journal de la mise en sourdine (un seul par délai) : %+v", logs)
	}

	now = now.Add(2 * time.Minute)
	e.evalAll()
	if len(bans) != 0 || len(logs) != 2 || !logs[1].Silenced {
		t.Fatalf("après le délai, toujours en sourdine : bans %v, journal %+v", bans, logs)
	}

	now = now.Add(time.Hour)
	e.evalAll()
	if len(bans) != 1 || len(logs) != 3 || logs[2].Silenced || !logs[2].ActionTaken {
		t.Fatalf("après la fin de la mise en sourdine : bans %v, journal %+v", bans, logs)
	}
}

func TestFutureSilenceWindowDoesNotApplyYet(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	fired := 0
	e := New(nopLogger{}, Deps{
		GetRepeatBanIP: func(time.Time, int) (string, int) { return "203.0.113.7", 5 },
		BanIP:          func(string, string, time.Duration) error { fired++; return nil },
	})
	e.now = func() time.Time { return now }
	e.ReplaceRules([]Rule{{ID: "r1", Enabled: true, Condition: Condition{Type: CondBanRepeat}, Action: Action{Type: ActionBanIP},
		SilenceWindows: []SilenceWindow{{Starts: now.Add(time.Hour), Ends: now.Add(2 * time.Hour)}}}})
	e.evalAll()
	if fired != 1 {
		t.Fatalf("fenêtre à venir appliquée trop tôt : %d", fired)
	}
}
