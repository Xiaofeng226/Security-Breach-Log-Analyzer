// Declarative Pipeline for Security Breach Log Analyzer
// Requires Jenkins plugins: Docker Pipeline, Kubernetes CLI, Go

pipeline {
    // Run every stage inside a Go 1.21 Docker container
    agent {
        docker {
            image 'golang:1.21-alpine'
            args '-v /var/run/docker.sock:/var/run/docker.sock'
        }
    }

    environment {
        DOCKER_IMAGE    = 'xiaofeng226/security-breach-analyzer'
        DOCKER_CREDS    = credentials('dockerhub-credentials')  // Set in Jenkins > Credentials
        KUBECONFIG_CRED = credentials('kubeconfig')             // Set in Jenkins > Credentials
        GO_FLAGS        = '-v'
        GOCACHE         = '/tmp/go-cache'
        GOPATH          = '/tmp/go'
    }

    // Trigger a build on every push to GitHub
    triggers {
        githubPush()
    }

    stages {

        // ── Stage 1: Checkout ──────────────────────────────────────────────────
        stage('Checkout') {
            steps {
                checkout scm
                sh 'go version'
                sh 'go env'
            }
        }

        // ── Stage 2: Lint & Vet ────────────────────────────────────────────────
        // go vet catches common mistakes (unreachable code, wrong format verbs, etc.)
        stage('Lint & Vet') {
            steps {
                sh 'go mod download'
                sh 'go vet ./...'
            }
        }

        // ── Stage 3: Test ──────────────────────────────────────────────────────
        // Runs all tests with race detector and produces a coverage report
        stage('Test') {
            steps {
                sh 'go test ${GO_FLAGS} -coverprofile=coverage.out ./...'
                sh 'go tool cover -func=coverage.out'
            }
            post {
                always {
                    // Archive the coverage report so it's visible in Jenkins UI
                    archiveArtifacts artifacts: 'coverage.out', fingerprint: true
                }
            }
        }

        // ── Stage 4: Build Binary ──────────────────────────────────────────────
        // Compiles a static Linux binary (CGO disabled for Docker compatibility)
        stage('Build Binary') {
            steps {
                sh '''
                    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
                    go build \
                        -ldflags="-s -w -X main.version=${GIT_COMMIT}" \
                        -o bin/security-analyzer .
                '''
                archiveArtifacts artifacts: 'bin/security-analyzer', fingerprint: true
            }
        }

        // ── Stage 5: Build & Push Docker Image ────────────────────────────────
        // Only runs on the main branch — not on feature branches or PRs
        stage('Docker Build & Push') {
            when {
                branch 'main'
            }
            steps {
                script {
                    def shortSha = GIT_COMMIT.take(7)
                    def imageTag = "${DOCKER_IMAGE}:sha-${shortSha}"
                    def latestTag = "${DOCKER_IMAGE}:latest"

                    // Build the image
                    sh "docker build -t ${imageTag} -t ${latestTag} ."

                    // Push both tags to Docker Hub
                    sh "echo ${DOCKER_CREDS_PSW} | docker login -u ${DOCKER_CREDS_USR} --password-stdin"
                    sh "docker push ${imageTag}"
                    sh "docker push ${latestTag}"

                    // Store the tag so the deploy stage can reference it
                    env.IMAGE_TAG = imageTag
                }
            }
        }

        // ── Stage 6: Deploy to Kubernetes ─────────────────────────────────────
        // Rolls out the new Docker image to the threat-detector Deployment
        stage('Deploy to Kubernetes') {
            when {
                branch 'main'
            }
            steps {
                script {
                    // Write the kubeconfig from Jenkins credentials
                    writeFile file: 'kubeconfig.yaml', text: KUBECONFIG_CRED

                    sh '''
                        export KUBECONFIG=kubeconfig.yaml

                        # Roll out the new image
                        kubectl set image deployment/threat-detector \
                            threat-detector=${IMAGE_TAG} \
                            --namespace security-pipeline

                        # Block until rollout completes (or times out after 2 min)
                        kubectl rollout status deployment/threat-detector \
                            --namespace security-pipeline \
                            --timeout=120s
                    '''
                }
            }
            post {
                failure {
                    // Auto-rollback if the deployment fails
                    sh '''
                        export KUBECONFIG=kubeconfig.yaml
                        echo "Deployment failed — rolling back..."
                        kubectl rollout undo deployment/threat-detector \
                            --namespace security-pipeline
                    '''
                }
                always {
                    // Never leave kubeconfig sitting on disk
                    sh 'rm -f kubeconfig.yaml'
                }
            }
        }
    }

    // ── Global post actions ────────────────────────────────────────────────────
    post {
        success {
            echo "Pipeline passed. Image deployed: ${env.IMAGE_TAG ?: 'N/A (not main branch)'}"
        }
        failure {
            echo "Pipeline failed at stage: ${env.STAGE_NAME}"
        }
        always {
            // Clean up the workspace after every run
            cleanWs()
        }
    }
}
