#!/bin/bash

# GhostScan Usage Examples
# This script demonstrates various ways to use GhostScan

echo "=== GhostScan Usage Examples ==="
echo

# Build the application first
echo "Building GhostScan..."
make build
echo

# Basic scan
echo "1. Basic Ghost CMS detection:"
echo "./build/ghostscan --url https://ghost.org"
echo

# Verbose scan with enumeration
echo "2. Verbose scan with theme and user enumeration:"
echo "./build/ghostscan --url https://ghost.org --verbose --enumerate themes,users"
echo

# Full enumeration
echo "3. Full component enumeration:"
echo "./build/ghostscan --url https://ghost.org --enumerate themes,users,posts,tags,integrations"
echo

# Brute force attack
echo "4. Brute force attack with custom wordlists:"
echo "./build/ghostscan --url https://ghost.org --brute-force --userlist wordlists/usernames.txt --passlist wordlists/passwords.txt"
echo

# JSON output
echo "5. Scan with JSON output:"
echo "./build/ghostscan --url https://ghost.org --format json --output results.json"
echo

# Custom user agent and timeout
echo "6. Scan with custom user agent and timeout:"
echo "./build/ghostscan --url https://ghost.org --user-agent 'Mozilla/5.0 (Custom Scanner)' --timeout 60"
echo

# High-performance scan
echo "7. High-performance scan with more threads:"
echo "./build/ghostscan --url https://ghost.org --threads 20 --enumerate themes,users"
echo

# Comprehensive security assessment
echo "8. Comprehensive security assessment:"
echo "./build/ghostscan --url https://ghost.org --verbose --enumerate themes,users,posts,tags,integrations --brute-force --format json --output comprehensive_scan.json"
echo

# Scan multiple targets (example loop)
echo "9. Scanning multiple targets:"
echo "for target in https://site1.com https://site2.com https://site3.com; do"
echo "    echo \"Scanning \$target...\""
echo "    ./build/ghostscan --url \$target --enumerate themes,users --output \"scan_\$(basename \$target).txt\""
echo "done"
echo

# Silent scan (no colored output)
echo "10. Silent scan for automation:"
echo "./build/ghostscan --url https://ghost.org --no-color --format json --output automated_scan.json"
echo

echo "=== Example Commands You Can Run ==="
echo

# Demonstrate help
echo "Showing help:"
./build/ghostscan --help
echo

# Example with a real target (Ghost.org blog)
echo "Example scan against Ghost.org (demo):"
echo "Note: This is for demonstration purposes only. Always ensure you have permission to scan targets."
echo
echo "Command: ./build/ghostscan --url https://ghost.org --verbose --enumerate themes,users --timeout 30"
echo
echo "Uncomment the line below to run the actual scan:"
echo "# ./build/ghostscan --url https://ghost.org --verbose --enumerate themes,users --timeout 30"
echo

echo "=== Security Testing Scenarios ==="
echo

echo "Scenario 1: Quick Ghost detection"
echo "./build/ghostscan --url TARGET_URL"
echo

echo "Scenario 2: Theme vulnerability assessment"
echo "./build/ghostscan --url TARGET_URL --enumerate themes --verbose"
echo

echo "Scenario 3: User enumeration for social engineering assessment"
echo "./build/ghostscan --url TARGET_URL --enumerate users --verbose"
echo

echo "Scenario 4: Authentication security testing"
echo "./build/ghostscan --url TARGET_URL --brute-force --userlist custom_users.txt --passlist custom_passwords.txt"
echo

echo "Scenario 5: Comprehensive security audit"
echo "./build/ghostscan --url TARGET_URL --verbose --enumerate themes,users,posts,tags,integrations --brute-force --format json --output security_audit.json"
echo

echo "=== Tips and Best Practices ==="
echo
echo "1. Always ensure you have permission to scan the target"
echo "2. Start with basic detection before running comprehensive scans"
echo "3. Use --verbose flag for detailed information during testing"
echo "4. Save results in JSON format for further analysis"
echo "5. Adjust --threads based on target server capacity"
echo "6. Use custom wordlists for better brute force results"
echo "7. Monitor scan progress and adjust timeout if needed"
echo "8. Review results carefully and verify findings manually"
echo

echo "=== Integration Examples ==="
echo
echo "Integration with other tools:"
echo
echo "# Combine with nmap for port discovery"
echo "nmap -p 80,443,2368 TARGET_IP && ./build/ghostscan --url http://TARGET_IP:2368"
echo
echo "# Use with curl for initial reconnaissance"
echo "curl -I TARGET_URL && ./build/ghostscan --url TARGET_URL"
echo
echo "# Chain with subdomain enumeration"
echo "subfinder -d DOMAIN | httpx | while read url; do ./build/ghostscan --url \$url; done"
echo

echo "=== Automation Examples ==="
echo
echo "# Automated scanning script"
echo "#!/bin/bash"
echo "TARGETS_FILE=\"targets.txt\""
echo "RESULTS_DIR=\"results\""
echo "mkdir -p \$RESULTS_DIR"
echo "while IFS= read -r target; do"
echo "    echo \"Scanning \$target...\""
echo "    filename=\$(echo \$target | sed 's|https\\?://||' | sed 's|/|_|g')"
echo "    ./build/ghostscan --url \"\$target\" --format json --output \"\$RESULTS_DIR/\$filename.json\""
echo "done < \"\$TARGETS_FILE\""
echo

echo "Script completed. Check the examples above for various usage scenarios."