#!/bin/bash

# OpenGrep + SonarQube Integration Setup
# Usage: ./setup.sh

echo "🚀 Setting up OpenGrep + SonarQube integration..."

# Step 1: Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is required but not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker &> /dev/null || ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose is required but not available. Please install Docker Compose first."
    exit 1
fi

# Step 2: Check if services are already running
if docker ps | grep -q "sonarqube\|opengrep\|postgresql"; then
    echo "✅ Services are already running! Skipping startup..."
    echo "   • SonarQube: $(docker ps --filter name=sonarqube --format '{{.Status}}')"
    echo "   • PostgreSQL: $(docker ps --filter name=postgresql --format '{{.Status}}')" 
    echo "   • OpenGrep: $(docker ps --filter name=opengrep --format '{{.Status}}')"
else
    echo "📦 Starting Docker services (SonarQube, PostgreSQL, OpenGrep)..."
    if [ -f "docker-compose.yml" ]; then
        docker compose up -d
    else
        echo "❌ docker-compose.yml not found in current directory."
        echo "Please run this script from the directory containing your docker-compose.yml"
        exit 1
    fi
    
    # Wait for services to be ready
    echo "⏳ Waiting for services to initialize..."
    echo "   • PostgreSQL starting..."
    sleep 10
    echo "   • SonarQube starting..."
    sleep 20
    echo "   • OpenGrep container ready..."
fi

# Step 4: Check if SonarQube is ready
echo "🔍 Checking SonarQube status..."
timeout 180 bash -c 'until curl -s http://localhost:9000/api/system/status | grep -q "UP"; do echo "   Waiting for SonarQube to be ready..."; sleep 10; done'

if curl -s http://localhost:9000/api/system/status | grep -q "UP"; then
    echo "✅ SonarQube is ready!"
else
    echo "⚠️  SonarQube is still starting. You can continue - it should be ready soon."
fi

# Step 5: Check OpenGrep installation in container
echo "🔍 Verifying OpenGrep installation..."
if docker-compose exec -T opengrep opengrep --version &>/dev/null; then
    echo "✅ OpenGrep is installed and ready!"
else
    echo "⚠️  OpenGrep is still installing in the container..."
fi

# Step 6: Install SonarQube Scanner locally if not present
echo "🔧 Checking SonarQube Scanner..."
if ! command -v sonar-scanner &> /dev/null; then
    echo "📥 Installing SonarQube Scanner..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install sonar-scanner
        else
            echo "❌ Please install Homebrew first, or download SonarQube Scanner manually"
            echo "   Download from: https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/"
            exit 1
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux - try npm first, then provide manual instructions
        if command -v npm &> /dev/null; then
            echo "   Installing via npm..."
            npm install -g sonar-scanner
        else
            echo "❌ Please install SonarQube Scanner manually:"
            echo "   Option 1: Install Node.js/npm, then run: npm install -g sonar-scanner"
            echo "   Option 2: Download from: https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/"
            exit 1
        fi
    else
        echo "❌ Please install SonarQube Scanner manually:"
        echo "   Download from: https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/"
        exit 1
    fi
fi

# Step 7: Make analyze script executable
chmod +x analyze.sh

# Step 8: Create sample OpenGrep rules (optional)
mkdir -p custom-rules
cat > custom-rules/sample-security.yaml << 'EOF'
rules:
  - id: hardcoded-password
    pattern: |
      password = "$PASSWORD"
    message: "Hardcoded password detected"
    languages: [python, javascript, java]
    severity: ERROR
    
  - id: sql-injection-risk
    pattern: |
      execute("SELECT * FROM users WHERE id = " + $ID)
    message: "Potential SQL injection vulnerability"
    languages: [python, java, javascript]
    severity: WARNING
EOF

echo "✅ Setup completed successfully!"
echo ""
echo "🎯 Next Steps:"
echo ""
echo "1. 🌐 Open SonarQube: http://localhost:9000"
echo "   • Default login: admin / admin"
echo "   • You'll be prompted to change the password"
echo ""
echo "2. 🔑 Create a Project Token:"
echo "   • Go to: My Account → Security → Generate Token"
echo "   • Project: $PROJECT_KEY"
echo "   • Copy the token"
echo ""
echo "3. ⚙️  Update Configuration:"
echo "   • Edit analyze.sh"
echo "   • Replace SONAR_TOKEN with your token"
echo "   • Update PROJECT_KEY if needed"
echo ""
echo "4. 🚀 Run Analysis:"
echo "   • Execute: ./analyze.sh"
echo ""
echo "🔗 Your Services:"
echo "   • SonarQube: http://localhost:9000"
echo "   • PostgreSQL: localhost:5432 (user: sonar, pass: sonar)"
echo "   • OpenGrep: Ready in Docker container"
echo ""
echo "📁 Generated Files:"
echo "   • custom-rules/sample-security.yaml (example rules)"
echo "   • reports/ (will contain analysis results)"
echo ""
echo "💡 Pro Tips:"
echo "   • Add custom OpenGrep rules in custom-rules/ folder"
echo "   • All security findings will appear in SonarQube as External Issues"
echo "   • Use 'docker-compose logs opengrep' to debug OpenGrep issues"
echo "   • Use 'docker-compose logs sonarqube' to debug SonarQube issues"
echo ""
echo "🎉 You're all set! Run './analyze.sh' to start your first analysis."
