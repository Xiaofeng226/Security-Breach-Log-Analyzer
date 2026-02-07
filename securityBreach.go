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

// processEvents reads events from Kafka and analyzes them
func (td *ThreatDetector) processEvents(workerID int) {
	defer td.wg.Done()

	log.Printf("Worker %d started", workerID)

	for {
		// Read message from Kafka
		msg, err := td.kafkaReader.ReadMessage(td.ctx)
		if err != nil {
			if err == context.Canceled {
				log.Printf("Worker %d shutting down", workerID)
				return
			}
			log.Printf("Worker %d error reading message: %v", workerID, err)
			continue
		}

		// Parse event
		var event SecurityEvent
		if err := json.Unmarshal(msg.Value, &event); err != nil {
			log.Printf("Worker %d error parsing event: %v", workerID, err)
			continue
		}

		// Detect threats
		td.detectThreats(event)
	}
}

// detectThreats analyzes an event for potential threats
func (td *ThreatDetector) detectThreats(event SecurityEvent) {
	// 1. Check for brute force attacks
	if td.isBruteForce(event) {
		alert := ThreatAlert{
			AlertID:    fmt.Sprintf("BF-%d", time.Now().Unix()),
			Timestamp:  time.Now(),
			Severity:   "HIGH",
			ThreatType: "BRUTE_FORCE",
			SourceIP:   event.SourceIP,
			Details:    fmt.Sprintf("Brute force attack detected from %s", event.SourceIP),
		}
		td.alertChan <- alert
	}

	// 2. Check for privilege escalation
	if td.isPrivilegeEscalation(event) {
		alert := ThreatAlert{
			AlertID:    fmt.Sprintf("PE-%d", time.Now().Unix()),
			Timestamp:  time.Now(),
			Severity:   "MEDIUM",
			ThreatType: "PRIVILEGE_ESCALATION",
			SourceIP:   event.SourceIP,
			Details:    fmt.Sprintf("Privilege escalation attempt by %s", event.User),
		}
		td.alertChan <- alert
	}

	// 3. Check for suspicious user activity
	if td.isSuspiciousUser(event) {
		alert := ThreatAlert{
			AlertID:    fmt.Sprintf("SU-%d", time.Now().Unix()),
			Timestamp:  time.Now(),
			Severity:   "HIGH",
			ThreatType: "SUSPICIOUS_USER",
			SourceIP:   event.SourceIP,
			Details:    fmt.Sprintf("Invalid user login attempts from %s", event.SourceIP),
		}
		td.alertChan <- alert
	}

}

// isBruteForce detects brute force authentication attacks
func (td *ThreatDetector) isBruteForce(event SecurityEvent) bool {
	// Only check failed authentication events
	if event.EventType != "authentication" || event.Result != "failed" {
		return false
	}

	// Use Redis to track failed attempts per IP
	key := fmt.Sprintf("failed_auth:%s", event.SourceIP)
	
	// Increment counter
	count, err := td.redisClient.Incr(td.ctx, key).Result()
	if err != nil {
		log.Printf("Redis error: %v", err)
		return false
	}

	// Set expiration (5 minute window)
	td.redisClient.Expire(td.ctx, key, 5*time.Minute)

	// Threshold: 5 failed attempts in 5 minutes
	return count >= 5
}


// isPrivilegeEscalation detects privilege escalation attempts
func (td *ThreatDetector) isPrivilegeEscalation(event SecurityEvent) bool {
	// Check for sudo commands or privilege changes
	if strings.Contains(strings.ToLower(event.Action), "sudo") ||
	   strings.Contains(strings.ToLower(event.EventType), "privilege") {
		
		// Check if targeting sensitive files/commands
		sensitivePatterns := []string{
			"/etc/shadow",
			"/etc/passwd",
			"/root",
			"chmod 777",
			"useradd",
		}

		for _, pattern := range sensitivePatterns {
			if strings.Contains(strings.ToLower(event.RawLog), pattern) {
				return true
			}
		}
	}

	return false
}

// isSuspiciousUser detects suspicious user activity
func (td *ThreatDetector) isSuspiciousUser(event SecurityEvent) bool {
	// Check for invalid user login attempts
	if strings.Contains(strings.ToLower(event.RawLog), "invalid user") {
		key := fmt.Sprintf("invalid_user:%s", event.SourceIP)
		
		count, err := td.redisClient.Incr(td.ctx, key).Result()
		if err != nil {
			return false
		}

		td.redisClient.Expire(td.ctx, key, 5*time.Minute)
		
		// Threshold: 3 invalid users in 5 minutes
		return count >= 3
	}

	return false
}
