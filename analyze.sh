#!/bin/bash

# Flexible OpenGrep + SonarQube Analysis Script
# Run from any repository directory - reports will be generated here
# Usage: ./analyze.sh

# Configuration
SONAR_HOST_URL="http://localhost:9000"
SONAR_TOKEN="TOKEN"
PROJECT_KEY="PROJECT_KEY"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
echo_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
echo_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Get current directory (repository being analyzed)
REPO_DIR=$(pwd)
echo_info "🚀 Starting OpenGrep + SonarQube analysis..."
echo_info "📁 Repository: $REPO_DIR"

# Create reports directory in current repo
mkdir -p reports

# Check if OpenGrep container exists
if ! docker ps -a | grep -q "opengrep"; then
    echo_error "❌ OpenGrep container not found!"
    echo_info "Please start the SonarQube + OpenGrep services first from your SonarQube directory"
    exit 1
fi

# Step 1: Use existing OpenGrep container
echo_info "🔍 Running OpenGrep security analysis..."
# Clear previous analysis files and copy source code to opengrep workspace
echo_info "🧹 Clearing previous analysis workspace..."
docker exec opengrep sh -c "cd /workspace && rm -rf source && mkdir source"
docker cp "$REPO_DIR/." opengrep:/workspace/source/
docker exec opengrep sh -c "
    cd /workspace &&
    mkdir -p reports &&
    echo '🔍 Running OpenGrep scan on repository...' &&
    opengrep scan --config=auto \
                  --json-output=reports/opengrep-results.json \
                  --sarif-output=reports/opengrep-results.sarif \
                  source/ || echo 'OpenGrep scan completed with warnings'
        
        echo '✅ OpenGrep analysis completed'
        
        # Show summary
        if [ -f 'reports/opengrep-results.json' ]; then
            echo '📊 OpenGrep Results:'
            python3 -c \"
import json
try:
    with open('reports/opengrep-results.json', 'r') as f:
        data = json.load(f)
    results = data.get('results', [])
    print(f'  📋 Total findings: {len(results)}')
    if results:
        errors = [r for r in results if r.get('extra', {}).get('severity') == 'ERROR']
        warnings = [r for r in results if r.get('extra', {}).get('severity') == 'WARNING']
        infos = [r for r in results if r.get('extra', {}).get('severity') == 'INFO']
        print(f'  🔴 Critical: {len(errors)}')
        print(f'  🟡 Major: {len(warnings)}')
        print(f'  🔵 Minor: {len(infos)}')
        
        print('\\n  🔍 Sample findings:')
        for i, result in enumerate(results[:3]):
            rule_id = result.get('check_id', 'unknown')
            message = result.get('message', 'No message')[:60]
            file_path = result.get('path', 'unknown')
            print(f'    {i+1}. {rule_id} in {file_path}')
        if len(results) > 3:
            print(f'    ... and {len(results) - 3} more')
except Exception as e:
    print(f'  ❌ Error parsing results: {e}')
\"
        else
            echo '⚠️  No security issues found or analysis failed'
        fi
"

# Copy results back to local reports directory
mkdir -p reports
docker cp opengrep:/workspace/reports/opengrep-results.json reports/ 2>/dev/null || echo_warning "Could not copy JSON results"
docker cp opengrep:/workspace/reports/opengrep-results.sarif reports/ 2>/dev/null || echo_warning "Could not copy SARIF results"

# Step 1.5: Run Cppcheck Static Analyzer for C/C++ files
echo_info "🧐 Checking for C/C++ files..."
CPP_FILES=$(find . -name "*.cpp" -o -name "*.c" -o -name "*.h" -o -name "*.hpp" | grep -v "/\." | head -20)
if [ ! -z "$CPP_FILES" ]; then
    echo_info "🔍 Running Cppcheck Static Analyzer on C/C++ files..."
    mkdir -p reports/cppcheck
    
    # Run Cppcheck with comprehensive analysis
    echo_info "🔍 Running comprehensive Cppcheck analysis..."
    cppcheck --enable=all \
             --inconclusive \
             --std=c++17 \
             --xml \
             --xml-version=2 \
             --output-file=reports/cppcheck/cppcheck-results.xml \
             --suppress=missingIncludeSystem \
             --suppress=unusedFunction \
             --suppress=cstyleCast \
             --suppress=missingOverride \
             --ignore=build/ \
             --ignore=CMakeFiles/ \
             --force \
             . || echo_warning "Cppcheck analysis completed with warnings"
    
    if [ -f "reports/cppcheck/cppcheck-results.xml" ]; then
        echo_success "✅ Cppcheck Static Analyzer completed"
        
        # Show Cppcheck results summary
        python3 -c "
import xml.etree.ElementTree as ET
try:
    tree = ET.parse('reports/cppcheck/cppcheck-results.xml')
    root = tree.getroot()
    errors = root.findall('.//error')
    print(f'  📋 Cppcheck findings: {len(errors)}')
    
    # Count by severity
    severities = {}
    for error in errors:
        severity = error.get('severity', 'unknown')
        severities[severity] = severities.get(severity, 0) + 1
    
    for sev, count in severities.items():
        if sev == 'error':
            print(f'  🔴 {sev.capitalize()}: {count}')
        elif sev == 'warning':
            print(f'  🟡 {sev.capitalize()}: {count}')
        else:
            print(f'  🔵 {sev.capitalize()}: {count}')
    
    # Show sample findings
    print('\\n  🔍 Sample findings:')
    for i, error in enumerate(errors[:3]):
        error_id = error.get('id', 'unknown')
        msg = error.get('msg', 'No message')[:60]
        file_path = error.get('file', 'unknown')
        line = error.get('line', '0')
        print(f'    {i+1}. {error_id}: {msg} at {file_path}:{line}')
    if len(errors) > 3:
        print(f'    ... and {len(errors) - 3} more')
        
except Exception as e:
    print(f'  ❌ Error parsing Cppcheck results: {e}')
"
    else
        echo_warning "⚠️  No Cppcheck output found"
    fi
else
    echo_info "ℹ️  No C/C++ files found, skipping Cppcheck analysis"
fi

# Step 2: Convert results for SonarQube using new 10.8+ format
echo_info "🔄 Converting results for SonarQube 10.8+..."
python3 << 'EOF'
import json
import os

# Check for both OpenGrep and Cppcheck results
opengrep_exists = os.path.exists('reports/opengrep-results.json')
cppcheck_exists = os.path.exists('reports/cppcheck/cppcheck-results.xml')

if not opengrep_exists and not cppcheck_exists:
    print("⚠️  No results to convert")
    exit(0)

try:
    # Load OpenGrep results if available
    opengrep_data = {}
    if opengrep_exists:
        with open('reports/opengrep-results.json', 'r') as f:
            opengrep_data = json.load(f)
    
    # Load Cppcheck XML results if available  
    cppcheck_data = {}
    if cppcheck_exists:
        import xml.etree.ElementTree as ET
        tree = ET.parse('reports/cppcheck/cppcheck-results.xml')
        cppcheck_data = tree.getroot()

    def get_impacts_and_severity(opengrep_severity):
        """Map OpenGrep severities to SonarQube format (both old and new)"""
        if opengrep_severity == 'ERROR':
            return {
                'severity': 'CRITICAL',
                'impacts': [
                    {"softwareQuality": "SECURITY", "severity": "HIGH"},
                    {"softwareQuality": "RELIABILITY", "severity": "HIGH"}
                ]
            }
        elif opengrep_severity == 'WARNING':
            return {
                'severity': 'MAJOR',
                'impacts': [
                    {"softwareQuality": "SECURITY", "severity": "MEDIUM"},
                    {"softwareQuality": "MAINTAINABILITY", "severity": "MEDIUM"}
                ]
            }
        else:  # INFO
            return {
                'severity': 'INFO',
                'impacts': [
                    {"softwareQuality": "MAINTAINABILITY", "severity": "LOW"}
                ]
            }

    # Collect unique rules first
    rules_dict = {}
    issues = []

    for result in opengrep_data.get('results', []):
        rule_id = result.get('check_id', 'unknown')
        opengrep_severity = result.get('extra', {}).get('severity', 'WARNING')
        
        # Create rule if not exists  
        if rule_id not in rules_dict:
            issue_type = 'VULNERABILITY'
            clean_code_attr = 'CONVENTIONAL'
            
            if 'performance' in rule_id.lower():
                issue_type = 'CODE_SMELL'
                clean_code_attr = 'EFFICIENT'
            elif 'bug' in rule_id.lower():
                issue_type = 'BUG'
                clean_code_attr = 'LOGICAL'
            
            severity_data = get_impacts_and_severity(opengrep_severity)
            
            # Try to get more detailed info from extra fields
            extra_info = result.get('extra', {})
            
            # Use the detailed message from extra, fallback to basic message
            detailed_message = extra_info.get('message', result.get('message', 'Security issue detected by OpenGrep'))
            
            # Build enhanced description with HTML formatting for SonarQube
            description_parts = [detailed_message]
            
            # Add metadata info if available
            if 'metadata' in extra_info:
                metadata = extra_info['metadata']
                if isinstance(metadata, dict):
                    
                    # Add a clear separator
                    description_parts.append("<hr>")
                    
                    # Add vulnerability classification section
                    classification_parts = []
                    
                    # Add CWE information
                    if 'cwe' in metadata and metadata['cwe']:
                        if isinstance(metadata['cwe'], list):
                            cwe_list = ', '.join(metadata['cwe'])
                            classification_parts.append(f"<strong>CWE</strong>: {cwe_list}")
                        else:
                            classification_parts.append(f"<strong>CWE</strong>: {metadata['cwe']}")
                    
                    # Add OWASP classification
                    if 'owasp' in metadata and metadata['owasp']:
                        if isinstance(metadata['owasp'], list):
                            owasp_list = ', '.join(metadata['owasp'])
                            classification_parts.append(f"<strong>OWASP</strong>: {owasp_list}")
                        else:
                            classification_parts.append(f"<strong>OWASP</strong>: {metadata['owasp']}")
                    
                    # Add vulnerability class
                    if 'vulnerability_class' in metadata and metadata['vulnerability_class']:
                        if isinstance(metadata['vulnerability_class'], list):
                            vuln_classes = ', '.join(metadata['vulnerability_class'])
                            classification_parts.append(f"<strong>Category</strong>: {vuln_classes}")
                    
                    if classification_parts:
                        description_parts.append("<p><strong>Security Classification:</strong><br>")
                        description_parts.append("<br>".join(classification_parts))
                        description_parts.append("</p>")
                    
                    # Add risk assessment section
                    risk_parts = []
                    if 'confidence' in metadata:
                        risk_parts.append(f"Confidence: {metadata['confidence']}")
                    if 'likelihood' in metadata:
                        risk_parts.append(f"Likelihood: {metadata['likelihood']}")
                    if 'impact' in metadata:
                        risk_parts.append(f"Impact: {metadata['impact']}")
                    
                    if risk_parts:
                        description_parts.append(f"<p><strong>Risk Assessment</strong>: {' | '.join(risk_parts)}</p>")
                    
                    # Add references section
                    if 'references' in metadata and metadata['references']:
                        description_parts.append("<p><strong>References:</strong><br>")
                        if isinstance(metadata['references'], list):
                            ref_links = []
                            for ref in metadata['references']:
                                ref_links.append(f'<a href="{ref}" target="_blank">{ref}</a>')
                            description_parts.append("<br>".join(ref_links))
                        else:
                            description_parts.append(f'<a href="{metadata["references"]}" target="_blank">{metadata["references"]}</a>')
                        description_parts.append("</p>")
                    
                    # Add rule source
                    if 'source' in metadata:
                        description_parts.append(f'<p><strong>Rule Documentation</strong>: <a href="{metadata["source"]}" target="_blank">View rule details</a></p>')
            
            enhanced_description = ''.join(description_parts)
            
            # Debug: Print the formatted description for the first rule
            if rule_id not in rules_dict:
                print(f"=== DEBUG: HTML Rule description for {rule_id} ===")
                print(repr(enhanced_description))
                print("=" * 60)
            
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f"OpenGrep: {rule_id.split('.')[-1]}",  # Use shorter name
                "description": enhanced_description,  # Use enhanced description
                "engineId": "opengrep",
                "cleanCodeAttribute": clean_code_attr,
                "type": issue_type,
                "severity": severity_data['severity'],
                "impacts": severity_data['impacts']
            }
        
        # Create issue
        file_path = result.get('path', '').lstrip('./')
        # Remove 'source/' prefix since that's just container artifact
        if file_path.startswith('source/'):
            file_path = file_path[7:]  # Remove 'source/' prefix
        
        # Use basic message for individual issue, detailed explanation is in rule description
        issue_message = result.get('message', 'Security issue detected')
            
        issue = {
            'ruleId': rule_id,
            'primaryLocation': {
                'message': issue_message,
                'filePath': file_path,
                'textRange': {
                    'startLine': result.get('start', {}).get('line', 1),
                    'endLine': result.get('end', {}).get('line', 1),
                    'startColumn': max(1, result.get('start', {}).get('col', 1)),
                    'endColumn': max(1, result.get('end', {}).get('col', 1))
                }
            }
        }
        issues.append(issue)
    
    # Process Cppcheck XML results
    if cppcheck_exists:
        print("📄 Processing Cppcheck Static Analyzer results...")
        
        def get_cppcheck_severity_data(severity):
            """Map Cppcheck severities to SonarQube format with impacts"""
            if severity == 'error':
                return {
                    'severity': 'CRITICAL',
                    'impacts': [
                        {"softwareQuality": "RELIABILITY", "severity": "HIGH"},
                        {"softwareQuality": "SECURITY", "severity": "HIGH"}
                    ]
                }
            elif severity == 'warning':
                return {
                    'severity': 'MAJOR',
                    'impacts': [
                        {"softwareQuality": "RELIABILITY", "severity": "MEDIUM"},
                        {"softwareQuality": "MAINTAINABILITY", "severity": "MEDIUM"}
                    ]
                }
            elif severity == 'style':
                return {
                    'severity': 'MINOR',
                    'impacts': [
                        {"softwareQuality": "MAINTAINABILITY", "severity": "LOW"}
                    ]
                }
            elif severity == 'performance':
                return {
                    'severity': 'MAJOR',
                    'impacts': [
                        {"softwareQuality": "MAINTAINABILITY", "severity": "MEDIUM"}
                    ]
                }
            elif severity == 'portability':
                return {
                    'severity': 'MINOR',
                    'impacts': [
                        {"softwareQuality": "MAINTAINABILITY", "severity": "LOW"}
                    ]
                }
            else:  # information
                return {
                    'severity': 'INFO',
                    'impacts': [
                        {"softwareQuality": "MAINTAINABILITY", "severity": "LOW"}
                    ]
                }
        
        # Process each error from Cppcheck XML
        for error in cppcheck_data.findall('.//error'):
            rule_id = f"cppcheck:{error.get('id', 'unknown')}"
            severity = error.get('severity', 'warning')
            msg = error.get('msg', 'C++ static analysis issue')
            verbose_msg = error.get('verbose', msg)
            
            # Create Cppcheck rule if not exists
            if rule_id not in rules_dict:
                severity_data = get_cppcheck_severity_data(severity)
                
                # Determine issue type based on rule ID
                issue_type = 'CODE_SMELL'
                clean_code_attr = 'CONVENTIONAL'
                
                error_id = error.get('id', '')
                if any(keyword in error_id.lower() for keyword in ['leak', 'memory', 'destructor', 'delete']):
                    issue_type = 'BUG'
                    clean_code_attr = 'LOGICAL'
                elif any(keyword in error_id.lower() for keyword in ['security', 'buffer', 'overflow', 'underflow']):
                    issue_type = 'VULNERABILITY'
                    clean_code_attr = 'TRUSTWORTHY'
                elif 'performance' in error_id.lower():
                    issue_type = 'CODE_SMELL'
                    clean_code_attr = 'EFFICIENT'
                
                # Build enhanced HTML description similar to OpenGrep format
                description_parts = [verbose_msg]
                
                # Add separator
                description_parts.append("<hr>")
                
                # Add Cppcheck-specific information
                classification_parts = []
                
                # Add severity classification
                classification_parts.append(f"<strong>Severity</strong>: {severity.capitalize()}")
                
                # Add rule ID
                classification_parts.append(f"<strong>Rule ID</strong>: {error.get('id', 'unknown')}")
                
                # Add category information based on rule type
                if 'leak' in error_id.lower() or 'destructor' in error_id.lower():
                    classification_parts.append("<strong>Category</strong>: Memory Management")
                elif 'buffer' in error_id.lower():
                    classification_parts.append("<strong>Category</strong>: Buffer Safety")
                elif 'null' in error_id.lower():
                    classification_parts.append("<strong>Category</strong>: Null Pointer")
                elif 'unused' in error_id.lower():
                    classification_parts.append("<strong>Category</strong>: Dead Code")
                elif 'uninit' in error_id.lower():
                    classification_parts.append("<strong>Category</strong>: Uninitialized Variable")
                
                if classification_parts:
                    description_parts.append("<p><strong>Analysis Classification:</strong><br>")
                    description_parts.append("<br>".join(classification_parts))
                    description_parts.append("</p>")
                
                # Add memory leak specific guidance
                if any(keyword in error_id.lower() for keyword in ['leak', 'destructor', 'delete']):
                    description_parts.append("<p><strong>Memory Management Guidance:</strong><br>")
                    description_parts.append("This issue indicates a potential memory leak. Consider implementing RAII (Resource Acquisition Is Initialization) pattern:<br>")
                    description_parts.append("• Add proper destructor with <code>delete[]</code> or <code>delete</code><br>")
                    description_parts.append("• Implement copy constructor and assignment operator (Rule of Three)<br>")
                    description_parts.append("• Consider using smart pointers like <code>std::unique_ptr</code> or <code>std::shared_ptr</code>")
                    description_parts.append("</p>")
                
                # Add documentation reference
                description_parts.append(f"<p><strong>Documentation:</strong> <a href='https://cppcheck.sourceforge.io/manual.html#{error_id}' target='_blank'>Cppcheck Rule Documentation</a></p>")
                description_parts.append("<p><strong>Analyzer:</strong> Cppcheck Static Analyzer</p>")
                
                enhanced_description = ''.join(description_parts)
                
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": f"Cppcheck: {error.get('id', 'Static Analysis').replace('_', ' ').replace('-', ' ').title()}",
                    "description": enhanced_description,
                    "engineId": "cppcheck",
                    "cleanCodeAttribute": clean_code_attr,
                    "type": issue_type,
                    "severity": severity_data['severity'],
                    "impacts": severity_data['impacts']
                }
            
            # Create Cppcheck issue for each location
            locations = error.findall('.//location')
            if not locations:
                # If no specific locations, create one issue with file info from error
                file_path = error.get('file', 'unknown')
                if file_path.startswith('./'):
                    file_path = file_path[2:]  # Remove './' prefix
                
                issue = {
                    'ruleId': rule_id,
                    'primaryLocation': {
                        'message': msg,
                        'filePath': file_path,
                        'textRange': {
                            'startLine': int(error.get('line', 1)),
                            'endLine': int(error.get('line', 1)),
                            'startColumn': 1,
                            'endColumn': 2
                        }
                    }
                }
                issues.append(issue)
            else:
                # Create issue for each location
                for location in locations:
                    file_path = location.get('file', 'unknown')
                    if file_path.startswith('./'):
                        file_path = file_path[2:]  # Remove './' prefix
                    
                    line_num = int(location.get('line', 1))
                    
                    issue = {
                        'ruleId': rule_id,
                        'primaryLocation': {
                            'message': msg,
                            'filePath': file_path,
                            'textRange': {
                                'startLine': line_num,
                                'endLine': line_num,
                                'startColumn': 1,
                                'endColumn': 2
                            }
                        }
                    }
                    issues.append(issue)

    # Create final format
    sonar_report = {
        "rules": list(rules_dict.values()),
        "issues": issues
    }

    with open('reports/opengrep-sonar-external.json', 'w') as f:
        json.dump(sonar_report, f, indent=2)

    # DEBUG: Print file path analysis
    print("=== DEBUG: File Path Analysis ===")
    all_files = set()
    for issue in issues:
        file_path = issue['primaryLocation']['filePath']
        all_files.add(file_path)
    
    print(f"📁 Unique files in issues: {len(all_files)}")
    for file_path in sorted(all_files):
        # Check if file actually exists
        import os
        exists = "✅" if os.path.exists(file_path) else "❌"
        print(f"  {exists} {file_path}")
    
    # Show current working directory context
    import os
    print(f"📂 Current working directory: {os.getcwd()}")
    print(f"📂 Files in current directory:")
    for item in sorted(os.listdir('.')):
        if os.path.isfile(item):
            print(f"  📄 {item}")
        elif os.path.isdir(item) and not item.startswith('.'):
            print(f"  📁 {item}/")
    print("=" * 50)

    # Count issues by source
    opengrep_issues = len([i for i in issues if not i['ruleId'].startswith('cppcheck:')])
    cppcheck_issues = len([i for i in issues if i['ruleId'].startswith('cppcheck:')])
    
    print(f"✅ Converted {len(issues)} total issues with {len(rules_dict)} rules for SonarQube 10.8+")
    if opengrep_issues > 0:
        print(f"   📊 OpenGrep: {opengrep_issues} security issues")
    if cppcheck_issues > 0:
        print(f"   🔍 Cppcheck Static Analyzer: {cppcheck_issues} C/C++ issues")
    
except Exception as e:
    print(f"❌ Error converting results: {e}")
    exit(1)
EOF

# Step 3: Check SonarQube status
echo_info "🔍 Checking SonarQube status..."
if curl -s http://localhost:9000/api/system/status | grep -q "UP"; then
    echo_success "✅ SonarQube is ready"
else
    echo_warning "⚠️  SonarQube may still be starting up"
fi

# Step 4: Run SonarQube analysis
echo_info "📊 Running SonarQube analysis..."
if command -v sonar-scanner >/dev/null 2>&1; then
    sonar-scanner \
        -Dsonar.host.url=$SONAR_HOST_URL \
        -Dsonar.token=$SONAR_TOKEN \
        -Dsonar.projectKey=$PROJECT_KEY \
        -Dsonar.projectName="$PROJECT_KEY (OpenGrep Security)" \
        -Dsonar.projectVersion=1.0 \
        -Dsonar.sources=. \
        -Dsonar.inclusions=**/*.cpp,**/*.c,**/*.h,**/*.hpp,**/*.cc \
        -Dsonar.exclusions=node_modules/**,vendor/**,.git/**,reports/**,*.yml,*.yaml,build/**,CMakeFiles/**,**/CMakeFiles/**,**/tests/** \
        -Dsonar.externalIssuesReportPaths=reports/opengrep-sonar-external.json
else
    echo_error "❌ sonar-scanner not installed!"
    echo_info "Install with: npm install -g sonar-scanner"
    exit 1
fi

# Step 5: Show results
echo_success "🎉 Analysis completed!"
echo ""
echo_info "📊 Results:"

# Count OpenGrep issues
if [ -f "reports/opengrep-results.json" ]; then
    OPENGREP_COUNT=$(python3 -c "
import json
try:
    with open('reports/opengrep-results.json', 'r') as f:
        data = json.load(f)
    print(len(data.get('results', [])))
except:
    print('0')
" 2>/dev/null)
    echo "   🔒 OpenGrep Security Issues: $OPENGREP_COUNT"
fi

# Count Cppcheck issues
if [ -f "reports/cppcheck/cppcheck-results.xml" ]; then
    CPPCHECK_COUNT=$(python3 -c "
import xml.etree.ElementTree as ET
try:
    tree = ET.parse('reports/cppcheck/cppcheck-results.xml')
    root = tree.getroot()
    errors = root.findall('.//error')
    print(len(errors))
except:
    print('0')
" 2>/dev/null)
    echo "   🔍 Cppcheck Static Analyzer Issues: $CPPCHECK_COUNT"
fi

echo "   📊 SonarQube Dashboard: $SONAR_HOST_URL/dashboard?id=$PROJECT_KEY"
echo "   📁 Reports Location: $REPO_DIR/reports/"
echo ""
echo_info "🎯 In SonarQube Issues tab:"
echo "   • Filter by 'External Engine: opengrep' for OpenGrep security issues"
echo "   • Filter by 'External Engine: cppcheck' for Cppcheck C/C++ issues"
echo "   • Look for memory leak issues marked as BUG with HIGH severity"
echo ""

# Offer to open browser
if command -v xdg-open >/dev/null 2>&1; then
    read -p "🌐 Open SonarQube dashboard? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        xdg-open "$SONAR_HOST_URL/dashboard?id=$PROJECT_KEY"
    fi
fi

echo_success "🚀 Integration complete!"
