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

// ThreatDetector processes security events and detects threats
type ThreatDetector struct {
	kafkaReader   *kafka.Reader
	kafkaWriter   *kafka.Writer
	redisClient   *redis.Client
	ctx           context.Context
	alertChan     chan ThreatAlert
	wg            sync.WaitGroup
}

// NewThreatDetector creates a new threat detector instance
func NewThreatDetector(kafkaBrokers []string, redisAddr string) *ThreatDetector {
	ctx := context.Background()

	// Kafka consumer (reads security events)
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     kafkaBrokers,
		Topic:       "security-events",
		GroupID:     "threat-detector-group",
		MinBytes:    10e3, // 10KB
		MaxBytes:    10e6, // 10MB
		MaxWait:     500 * time.Millisecond,
	})

	// Kafka producer (publishes alerts)
	writer := &kafka.Writer{
		Addr:     kafka.TCP(kafkaBrokers...),
		Topic:    "security-alerts",
		Balancer: &kafka.LeastBytes{},
	}

	// Redis client (for state management)
	redisClient := redis.NewClient(&redis.Options{
		Addr: redisAddr,
		DB:   0,
	})

	return &ThreatDetector{
		kafkaReader:   reader,
		kafkaWriter:   writer,
		redisClient:   redisClient,
		ctx:           ctx,
		alertChan:     make(chan ThreatAlert, 100),
	}
}

// Start begins processing security events
func (td *ThreatDetector) Start(numWorkers int) {
	log.Printf("Starting %d threat detector workers...", numWorkers)

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		td.wg.Add(1)
		go td.processEvents(i)
	}

	// Start alert publisher
	td.wg.Add(1)
	go td.publishAlerts()

	log.Println("Threat detector started successfully")
}