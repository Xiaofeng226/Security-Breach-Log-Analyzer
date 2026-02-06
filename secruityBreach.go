// Package main - Threat Detector Service
// Part of Distributed Security Event Pipeline
// Author: Xiaofeng Li (xiali@g.hmc.edu)

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/go-redis/redis/v8"
)

// SecurityEvent represents a normalized security event
type SecurityEvent struct {
	Timestamp  time.Time         `json:"timestamp"`
	Source     string            `json:"source"`
	SourceIP   string            `json:"source_ip"`
	EventType  string            `json:"event_type"`
	User       string            `json:"user"`
	Action     string            `json:"action"`
	Result     string            `json:"result"`
	RawLog     string            `json:"raw_log"`
	Metadata   map[string]string `json:"metadata"`
}

// ThreatAlert represents a detected security threat
type ThreatAlert struct {
	AlertID    string    `json:"alert_id"`
	Timestamp  time.Time `json:"timestamp"`
	Severity   string    `json:"severity"` // HIGH, MEDIUM, LOW
	ThreatType string    `json:"threat_type"`
	SourceIP   string    `json:"source_ip"`
	Details    string    `json:"details"`
	EventCount int       `json:"event_count"`
	RawEvents  []string  `json:"raw_events"`
}