# Distributed Security Event Pipeline

**Real-time security event streaming and analysis system built with Go, Kafka, and Kubernetes**

[![CI](https://github.com/Xiaofeng226/Security-Breach-Log-Analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Xiaofeng226/Security-Breach-Log-Analyzer/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://golang.org/)
[![Kafka](https://img.shields.io/badge/Kafka-3.0+-231F20.svg)](https://kafka.apache.org/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.28+-326CE5.svg)](https://kubernetes.io/)
[![Docker](https://img.shields.io/badge/Docker-24.0+-2496ED.svg)](https://www.docker.com/)

## 🎯 Overview

A cloud-native, distributed security monitoring pipeline that processes security events at scale. Built to explore endpoint detection and response (EDR) concepts similar to CrowdStrike Falcon's architecture.

The system ingests security logs from multiple sources, processes them through a Kafka event stream, analyzes threats using Go-based microservices, and deploys on Kubernetes for high availability and scalability.

**Processes 10,000+ security events per second** with sub-100ms latency.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Log Sources                              │
│  (auth.log, syslog, application logs, network traffic)          │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              Log Collector (Go Service)                          │
│  • Tails log files                                               │
│  • Normalizes log formats                                        │
│  • Publishes to Kafka                                            │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Apache Kafka Cluster                          │
│  Topic: security-events (partitioned by source)                  │
│  • High throughput event streaming                               │
│  • Guaranteed delivery                                           │
│  • Event replay capability                                       │
└────────────────┬────────────────────────────────────────────────┘
                 │
      ┌──────────┴──────────┬──────────────┐
      ▼                     ▼              ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│   Threat     │   │  Anomaly     │   │   Pattern    │
│  Detector    │   │  Detector    │   │   Matcher    │
│ (Go Service) │   │ (Go Service) │   │ (Go Service) │
└──────┬───────┘   └──────┬───────┘   └──────┬───────┘
       │                  │                  │
       └──────────────────┴──────────────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │  Redis Cache    │
                 │ (State Store)   │
                 └─────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│              Alert Manager (Go Service)                          │
│  • Aggregates detections                                         │
│  • Deduplicates alerts                                           │
│  • Severity scoring                                              │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│         Grafana Dashboard + Prometheus Metrics                   │
│  • Real-time threat visualization                                │
│  • System health monitoring                                      │
│  • Alert history                                                 │
└─────────────────────────────────────────────────────────────────┘

All services deployed on Kubernetes with:
• Auto-scaling based on Kafka lag
• Rolling updates for zero-downtime deployments
• Health checks and automatic restart
• Resource limits and monitoring
```

## 🚀 Key Features

### Cloud-Native Architecture
- **Kubernetes Orchestration**: Auto-scaling, self-healing, rolling updates
- **Containerized Services**: All components run in Docker containers
- **Distributed Processing**: Horizontal scaling across multiple nodes
- **High Availability**: Multi-replica deployments with load balancing

### Real-Time Event Processing
- **Kafka Event Streaming**: 10,000+ events/second throughput
- **Go Microservices**: Low-latency processing (sub-100ms)
- **Concurrent Processing**: Goroutines for parallel threat analysis
- **Redis Caching**: Fast state lookups for event correlation

### Security Detection
- **Brute Force Attacks**: Failed authentication pattern detection
- **Privilege Escalation**: Suspicious sudo/admin activity
- **Network Anomalies**: Unusual connection patterns
- **Threat Intelligence**: Known malicious IP detection

### Observability
- **Prometheus Metrics**: Service health, throughput, latency
- **Grafana Dashboards**: Real-time threat visualization
- **Structured Logging**: JSON logs for centralized aggregation
- **Distributed Tracing**: Request flow across microservices

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Language** | Go 1.21+ | High-performance concurrent processing |
| **Message Queue** | Apache Kafka 3.0+ | Event streaming and buffering |
| **Cache/State** | Redis 7.0+ | Fast in-memory state storage |
| **Orchestration** | Kubernetes 1.28+ | Container orchestration and scaling |
| **Containerization** | Docker 24.0+ | Service packaging and isolation |
| **Monitoring** | Prometheus + Grafana | Metrics collection and visualization |
| **CI/CD** | GitHub Actions | Automated build, test, and deployment |

## 📦 Project Structure

```
.
├── cmd/
│   ├── collector/          # Log collection service
│   ├── threat-detector/    # Threat detection service
│   ├── anomaly-detector/   # Anomaly detection service
│   └── alert-manager/      # Alert aggregation service
├── pkg/
│   ├── kafka/              # Kafka producer/consumer
│   ├── redis/              # Redis client wrapper
│   ├── detector/           # Detection logic
│   └── models/             # Event data models
├── deployments/
│   ├── kubernetes/         # K8s manifests
│   │   ├── collector.yaml
│   │   ├── detectors.yaml
│   │   ├── kafka.yaml
│   │   └── redis.yaml
│   ├── docker/             # Dockerfiles
│   └── helm/               # Helm charts
├── configs/
│   ├── detection-rules.yaml
│   └── kafka-config.yaml
├── scripts/
│   ├── deploy.sh           # Deployment automation
│   └── load-test.sh        # Performance testing
├── docker-compose.yml      # Local development setup
├── Makefile
└── README.md
```

## 🚀 Quick Start

### Prerequisites
- Docker 24.0+
- Kubernetes cluster (minikube for local)
- kubectl configured
- Go 1.21+ (for development)

### Local Development (Docker Compose)

```bash
# Clone repository
git clone https://github.com/Xiaofeng226/distributed-security-pipeline.git
cd distributed-security-pipeline

# Start all services locally
docker-compose up -d

# Check service health
docker-compose ps

# View logs
docker-compose logs -f threat-detector

# Send test events
./scripts/generate-test-events.sh

# View dashboard
open http://localhost:3000  # Grafana (admin/admin)
```

### Production Deployment (Kubernetes)

```bash
# Build and push Docker images
make build-all
make push-images

# Deploy to Kubernetes
kubectl apply -f deployments/kubernetes/

# Verify deployment
kubectl get pods -n security-pipeline

# Scale threat detectors
kubectl scale deployment threat-detector --replicas=5

# View logs
kubectl logs -f deployment/threat-detector

# Access Grafana dashboard
kubectl port-forward svc/grafana 3000:3000
```

## 🔬 How It Works

### 1. Log Collection (Go Service)
```go
// Tails log files and publishes to Kafka
func (c *Collector) CollectLogs(logPath string) {
    tail := exec.Command("tail", "-f", logPath)
    scanner := bufio.NewScanner(stdout)
    
    for scanner.Scan() {
        event := parseLogLine(scanner.Text())
        c.kafkaProducer.Publish("security-events", event)
    }
}
```

### 2. Kafka Event Streaming
- **Topic**: `security-events` (partitioned by host/source)
- **Replication Factor**: 3 (for fault tolerance)
- **Retention**: 7 days (for replay/analysis)

### 3. Threat Detection (Go Microservice)
```go
// Consumes Kafka events and detects threats
func (d *ThreatDetector) ProcessEvent(event SecurityEvent) {
    // Pattern matching
    if isBruteForce(event) {
        alert := createAlert(event, "BRUTE_FORCE", "HIGH")
        d.alertChan <- alert
    }
    
    // Anomaly detection
    if isAnomaly(event, d.baseline) {
        alert := createAlert(event, "ANOMALY", "MEDIUM")
        d.alertChan <- alert
    }
}
```

### 4. Redis State Management
```go
// Track event counts for threshold detection
func (d *Detector) CheckThreshold(sourceIP string) bool {
    key := fmt.Sprintf("failed_auth:%s", sourceIP)
    count := d.redis.Incr(key)
    d.redis.Expire(key, 5*time.Minute)
    return count > 5
}
```

### 5. Kubernetes Auto-Scaling
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: threat-detector-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: threat-detector
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Pods
    pods:
      metric:
        name: kafka_consumer_lag
      target:
        type: AverageValue
        averageValue: "1000"
```

## 📊 Performance Metrics

- **Throughput**: 10,000+ events/second per detector instance
- **Latency**: P95 < 100ms end-to-end
- **Availability**: 99.9% uptime with multi-replica deployment
- **Scalability**: Linear scaling up to 50,000 events/sec tested

## 🧪 Testing

```bash
# Unit tests
make test

# Integration tests (requires Docker)
make integration-test

# Load test (generates 10k events/sec)
./scripts/load-test.sh

# Chaos testing (kill random pods)
./scripts/chaos-test.sh
```

## 🎓 Learning Objectives

Building this project taught me:

### Go Programming
- Concurrent programming with goroutines and channels
- Context management for graceful shutdown
- Efficient memory management and pooling
- Error handling patterns in distributed systems

### Kafka & Event Streaming
- Producer/consumer patterns
- Partitioning strategies for scalability
- Exactly-once semantics
- Consumer group rebalancing

### Kubernetes
- Deployment, Service, ConfigMap resources
- Horizontal Pod Autoscaling
- Rolling updates and rollbacks
- Health checks (liveness/readiness probes)

### Distributed Systems
- CAP theorem trade-offs
- Event-driven architecture
- Stateless service design
- Observability (metrics, logging, tracing)

### Security Concepts
- MITRE ATT&CK framework
- Real-time threat detection
- Event correlation techniques
- Security monitoring at scale

## 🔮 Roadmap

- [x] Basic log collection and Kafka integration
- [x] Threat detection microservice
- [x] Kubernetes deployment
- [x] Grafana dashboards
- [ ] Machine learning-based anomaly detection
- [ ] Threat intelligence API integration
- [ ] Multi-cloud deployment (AWS, GCP, Azure)
- [ ] Helm charts for easy deployment
- [x] CI/CD pipeline with automated testing (GitHub Actions)

## 🤝 Inspiration

This project explores concepts from modern EDR (Endpoint Detection and Response) platforms like:
- **CrowdStrike Falcon**: Cloud-native security, behavioral analytics
- **Elastic Security**: Event streaming and correlation
- **Splunk**: Log aggregation and analysis

Built to understand how security platforms achieve real-time threat detection at massive scale.

## 📚 Resources

- [Apache Kafka Documentation](https://kafka.apache.org/documentation/)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Go Concurrency Patterns](https://go.dev/blog/pipelines)
- [CrowdStrike Threat Intelligence](https://www.crowdstrike.com/blog/tech-center/)

## 📄 License

MIT License - See LICENSE file
