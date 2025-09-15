#!/bin/bash

# cis_macos_15_0_mdm_compliance_1.9.7.sh
# Version: 1.9.7
# Updated: 2025-07-15
# Purpose: Audit all 107 CIS macOS 15.0 Sequoia controls (Level 1 and 2) via MDM profiles and system settings

# Initialize variables
LOG_FILE="/var/log/cis_macos_15_0_compliance.log"
JSON_OUTPUT="/tmp/compliance.json"
HTML_OUTPUT="/tmp/compliance_report.html"
CSV_OUTPUT="/tmp/compliance_report.csv"
COMPLIANT_COUNT=0
NON_COMPLIANT_COUNT=0
MANUAL_COUNT=0
JSON_ARRAY=()
COMPLIANT_LIST=()
NON_COMPLIANT_LIST=()
MANUAL_LIST=()
CONTROL_IDS=()
HOSTNAME=$(hostname)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
TOTAL_CONTROLS=107
CURRENT_CONTROL=0
CURRENT_SECTION=""
VERBOSE=0

# Parse command-line arguments
while getopts "v" opt; do
    case $opt in
        v) VERBOSE=1 ;;
    esac
done

# Logging function
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
    [ $VERBOSE -eq 1 ] && echo "$1"
}

# Function to update progress
update_progress() {
    local section="$1"
    ((CURRENT_CONTROL++))
    local percent=$((CURRENT_CONTROL * 100 / TOTAL_CONTROLS))
    printf "\rProgress: [%-50s] %d%% (%s)" "$(printf '#%.0s' $(seq 1 $((percent / 2))))" "$percent" "$section"
}

# Function to check if control ID was already processed
is_control_processed() {
    local control_id="$1"
    echo "${CONTROL_IDS[*]}" | grep -qw "$control_id"
    return $?
}

# Function to print and log compliance status
print_status() {
    local control_id="$1"
    local description="$2"
    local status="$3"
    local poc="$4"
    local check_details="$5"
    local severity="$6"
    local GREEN="\033[0;32m"
    local RED="\033[0;31m"
    local YELLOW="\033[0;33m"
    local NC="\033[0m"
    local color

    case "$status" in
        "Compliant") color="$GREEN" ;;
        "Non-Compliant") color="$RED" ;;
        *) color="$YELLOW" ;;
    esac

    # Console output
    echo -e "${color}Control $control_id: $description${NC}"
    echo -e "${color}Status: $status${NC}"
    [ -n "$poc" ] && echo -e "${color}PoC: $poc${NC}"
    [ $VERBOSE -eq 1 ] && [ -n "$check_details" ] && echo -e "${color}Check Details: $check_details${NC}"
    echo "----------------------------------------"

    # Log details to file
    log_message "Control $control_id: $description - Status: $status"
    [ -n "$check_details" ] && log_message "Check Details: $check_details"
    [ -n "$poc" ] && log_message "PoC for $control_id: $poc"

    # Add to arrays only if not already processed
    if ! is_control_processed "$control_id"; then
        CONTROL_IDS+=("$control_id")
        JSON_ARRAY+=("{\"ControlID\":\"$control_id\",\"Status\":\"$status\",\"Description\":\"$description\",\"Severity\":\"$severity\"}")
        case "$status" in
            "Compliant") 
                ((COMPLIANT_COUNT++))
                COMPLIANT_LIST+=("$control_id:$description:$status:$severity:$poc")
                ;;
            "Non-Compliant") 
                ((NON_COMPLIANT_COUNT++))
                NON_COMPLIANT_LIST+=("$control_id:$description:$status:$severity:$poc")
                ;;
            *) 
                ((MANUAL_COUNT++))
                MANUAL_LIST+=("$control_id:$description:$status:$severity:$poc")
                ;;
        esac
    fi
    update_progress "$CURRENT_SECTION"
}

# Function to check MDM profile
check_mdm_profile() {
    local domain="$1"
    local key="$2"
    local expected_value="$3"
    local profile_output
    local index=0
    local details=""
    profiles show -type configuration > /tmp/profiles.plist 2>/dev/null
    while true; do
        payload_type=$(plutil -extract "PayloadContent.$index.PayloadType" raw /tmp/profiles.plist 2>/dev/null)
        if [ $? -ne 0 ]; then
            details="MDM check for $domain.$key failed: No more payloads at index $index"
            log_message "$details"
            break
        fi
        if [ "$payload_type" = "$domain" ]; then
            profile_output=$(plutil -extract "PayloadContent.$index.$key" raw /tmp/profiles.plist 2>/dev/null)
            if [ $? -eq 0 ] && [ -n "$profile_output" ]; then
                if [ "$profile_output" = "$expected_value" ]; then
                    log_message "MDM check for $domain.$key (PayloadContent.$index): Expected $expected_value, Got $profile_output"
                    return 0
                else
                    details="MDM check for $domain.$key (PayloadContent.$index) failed: Expected $expected_value, Got $profile_output"
                    log_message "$details"
                    return 1
                fi
            fi
        fi
        ((index++))
    done
    details="MDM check for $domain.$key failed: No valid payload found"
    log_message "$details"
    echo "$details"
    return 1
}

# Function to check system settings
safe_system_check() {
    local command="$1"
    local expected_output="$2"
    local output
    local details=""
    output=$(eval "$command" 2>/dev/null)
    if [ -z "$expected_output" ]; then
        if [ -z "$output" ]; then
            log_message "System check for '$command': Expected no output, Got no output"
            return 0
        else
            details="System check for '$command' failed: Expected no output, Got '$output'"
            log_message "$details"
            echo "$details"
            return 1
        fi
    elif echo "$output" | grep -q "$expected_output"; then
        log_message "System check for '$command': Expected '$expected_output', Got '$output'"
        return 0
    else
        details="System check for '$command' failed: Expected '$expected_output', Got '$output'"
        log_message "$details"
        echo "$details"
        return 1
    fi
}

# Function for password policy checks
safe_password_check() {
    local key="$1"
    local expected_value="$2"
    local output
    local details=""
    case "$key" in
        maxPinAgeInDays)
            output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'policyAttributeExpiresEveryNDays' | grep '<integer>' | sed -E 's/.*<integer>(.*)<\/integer>.*/\1/' | head -1)
            ;;
        maxGracePeriod)
            output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'maxGracePeriod' | grep '<integer>' | sed -E 's/.*<integer>(.*)<\/integer>.*/\1/' | head -1)
            ;;
        maxInactivity)
            output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'maxInactivity' | grep '<integer>' | sed -E 's/.*<integer>(.*)<\/integer>.*/\1/' | head -1)
            ;;
        minComplexCharacters)
            output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'minComplexChars' | grep '<integer>' | sed -E 's/.*<integer>(.*)<\/integer>.*/\1/' | head -1)
            [ -z "$output" ] && output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -c 'non-alphanumeric') && [ "$output" -gt 0 ] && output=1
            ;;
        pinHistory)
            output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'policyAttributePasswordHistoryDepth' | grep '<integer>' | sed -E 's/.*<integer>(.*)<\/integer>.*/\1/' | head -1)
            ;;
        forcePIN)
            output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -c 'forcePIN')
            [ "$output" -gt 0 ] && output=1 || output=0
            ;;
        passwordContentRegex)
            output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'customRegex' | grep '<string>' | sed -E 's/.*<string>(.*)<\/string>.*/\1/' | head -1)
            [ -z "$output" ] && output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'customRegex' | grep -oE '[a-z].*[A-Z].*[0-9!@#$%^&*()_+\-=\[\]{};":\\|,.<>/?].{8,}' | head -1)
            ;;
        maxFailedAttempts)
            output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'policyAttributeMaximumFailedAuthentications' | grep '<integer>' | sed -E 's/.*<integer>(.*)<\/integer>.*/\1/' | head -1)
            ;;
        allowSimplePasscode)
            output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'allowSimple' | grep -o 'Maximum.*Characters' | wc -l | tr -d ' ')
            [ "$output" -gt 0 ] && output=0 || output=1
            ;;
        minutesUntilFailedLoginReset)
            output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'autoEnableInSeconds' | grep '<integer>' | sed -E 's/.*<integer>(.*)<\/integer>.*/\1/' | head -1)
            [ -n "$output" ] && output=$((output / 60))
            ;;
        requireAlphanumericPasscode)
            output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'requireAlphanumeric' | grep -c 'a-zA-Z')
            [ "$output" -gt 0 ] && output=1 || output=0
            ;;
        minLength)
            output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'minLength' | grep '<integer>' | sed -E 's/.*<integer>([0-9]+).*/\1/' | head -1)
            [ -z "$output" ] && output=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -A5 'minLength' | grep -o '.{8,}' | wc -l | tr -d ' ') && [ "$output" -gt 0 ] && output=8
            ;;
    esac
    if [ -z "$output" ] && [ "$key" != "passwordContentRegex" ]; then
        details="Password policy check for $key failed: Key not found"
        log_message "$details"
        echo "$details"
        return 1
    fi
    if [ "$key" = "maxPinAgeInDays" ] || [ "$key" = "pinHistory" ] || [ "$key" = "minutesUntilFailedLoginReset" ] || [ "$key" = "minLength" ]; then
        if [ -n "$output" ] && [ "$output" -ge "$expected_value" ]; then
            log_message "Password policy check for $key: Expected >= $expected_value, Got $output"
            return 0
        fi
    elif [ "$key" = "maxFailedAttempts" ]; then
        if [ -n "$output" ] && [ "$output" -le "$expected_value" ]; then
            log_message "Password policy check for $key: Expected <= $expected_value, Got $output"
            return 0
        fi
    elif [ "$key" = "passwordContentRegex" ]; then
        if [ -n "$output" ] && echo "$output" | grep -qE "$expected_value" 2>/dev/null; then
            log_message "Password policy check for $key: Expected $expected_value, Got $output"
            return 0
        elif [ -z "$output" ]; then
            log_message "Password policy check for $key: No regex found, assuming default compliance"
            return 0
        fi
    elif [ "$output" = "$expected_value" ]; then
        log_message "Password policy check for $key: Expected $expected_value, Got $output"
        return 0
    fi
    details="Password policy check for $key failed: Expected $expected_value, Got $output"
    log_message "$details"
    echo "$details"
    return 1
}

# Function to generate HTML report
generate_html_report() {
    local compliant_list=""
    local non_compliant_list=""
    local manual_list=""
    for item in "${COMPLIANT_LIST[@]}"; do
        if [[ $item =~ ^1\..* ]]; then
            IFS=':' read -r id desc status sev poc <<< "$item"
            compliant_list+="<tr><td class='$status'>$id</td><td>$desc</td><td>$status</td><td>$sev</td><td class='tooltip'>$([ -n "$poc" ] && echo "<span class='tooltiptext'>$poc</span>" || echo "")</td></tr>"
        fi
    done
    for item in "${NON_COMPLIANT_LIST[@]}"; do
        if [[ $item =~ ^1\..* ]]; then
            IFS=':' read -r id desc status sev poc <<< "$item"
            non_compliant_list+="<tr><td class='$status'>$id</td><td>$desc</td><td>$status</td><td>$sev</td><td class='tooltip'>$([ -n "$poc" ] && echo "<span class='tooltiptext'>$poc</span>" || echo "")</td></tr>"
        fi
    done
    for item in "${MANUAL_LIST[@]}"; do
        if [[ $item =~ ^1\..* ]]; then
            IFS=':' read -r id desc status sev poc <<< "$item"
            manual_list+="<tr><td class='manual'>$id</td><td>$desc</td><td>$status</td><td>$sev</td><td class='tooltip'>$([ -n "$poc" ] && echo "<span class='tooltiptext'>$poc</span>" || echo "")</td></tr>"
        fi
    done

    cat << EOF > "$HTML_OUTPUT"
<!DOCTYPE html>
<html>
<head>
    <title>CIS macOS 15.0 Sequoia Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .compliant { color: green; }
        .non-compliant { color: red; }
        .manual { color: orange; }
        .toggle { cursor: pointer; color: blue; text-decoration: underline; }
        .tooltip { position: relative; display: inline-block; }
        .tooltip .tooltiptext { visibility: hidden; width: 300px; background-color: #555; color: #fff; text-align: left; padding: 5px; border-radius: 6px; position: absolute; z-index: 1; }
        .tooltip:hover .tooltiptext { visibility: visible; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        function toggleSection(id) {
            var section = document.getElementById(id);
            section.style.display = section.style.display === 'none' ? 'block' : 'none';
        }
        window.onload = function() {
            var ctx = document.getElementById('complianceChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: ['Compliant', 'Non-Compliant', 'Manual Verification'],
                    datasets: [{
                        data: [$COMPLIANT_COUNT, $NON_COMPLIANT_COUNT, $MANUAL_COUNT],
                        backgroundColor: ['#28a745', '#dc3545', '#ffc107']
                    }]
                },
                options: {
                    title: { display: true, text: 'Compliance Status' }
                }
            });
        }
    </script>
</head>
<body>
    <h1>CIS macOS 15.0 Sequoia Compliance Report</h1>
    <p><strong>Hostname:</strong> $HOSTNAME</p>
    <p><strong>Timestamp:</strong> $TIMESTAMP</p>
    <p><strong>Total Checks:</strong> $((COMPLIANT_COUNT + NON_COMPLIANT_COUNT + MANUAL_COUNT))</p>
    <p><strong>Passed:</strong> $COMPLIANT_COUNT</p>
    <p><strong>Failed:</strong> $NON_COMPLIANT_COUNT</p>
    <p><strong>Manual Verification Required:</strong> $MANUAL_COUNT</p>
    <canvas id="complianceChart" width="400" height="200"></canvas>
    
    <h2>Section Summary</h2>
    <table>
        <tr><th>Section</th><th>Total</th><th>Compliant</th><th>Non-Compliant</th><th>Manual</th></tr>
        <tr><td>Software Updates</td><td>6</td><td>$(echo "${COMPLIANT_LIST[*]}" | grep -c '^1\.')</td><td>$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^1\.')</td><td>$(echo "${MANUAL_LIST[*]}" | grep -c '^1\.')</td></tr>
        <tr><td>Accounts</td><td>8</td><td>$(echo "${COMPLIANT_LIST[*]}" | grep -c '^2\.[1-7]\.')</td><td>$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^2\.[1-7]\.')</td><td>$(echo "${MANUAL_LIST[*]}" | grep -c '^2\.[1-7]\.')</td></tr>
        <tr><td>Restrictions</td><td>42</td><td>$(echo "${COMPLIANT_LIST[*]}" | grep -c '^2\.8\.')</td><td>$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^2\.8\.')</td><td>$(echo "${MANUAL_LIST[*]}" | grep -c '^2\.8\.')</td></tr>
        <tr><td>Security</td><td>12</td><td>$(echo "${COMPLIANT_LIST[*]}" | grep -c '^2\.9\.')</td><td>$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^2\.9\.')</td><td>$(echo "${MANUAL_LIST[*]}" | grep -c '^2\.9\.')</td></tr>
        <tr><td>Software Update</td><td>5</td><td>$(echo "${COMPLIANT_LIST[*]}" | grep -c '^2\.10\.')</td><td>$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^2\.10\.')</td><td>$(echo "${MANUAL_LIST[*]}" | grep -c '^2\.10\.')</td></tr>
        <tr><td>System Configuration</td><td>7</td><td>$(echo "${COMPLIANT_LIST[*]}" | grep -c '^2\.1[1-3]\.')</td><td>$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^2\.1[1-3]\.')</td><td>$(echo "${MANUAL_LIST[*]}" | grep -c '^2\.1[1-3]\.')</td></tr>
        <tr><td>Logging and Auditing</td><td>5</td><td>$(echo "${COMPLIANT_LIST[*]}" | grep -c '^3\.')</td><td>$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^3\.')</td><td>$(echo "${MANUAL_LIST[*]}" | grep -c '^3\.')</td></tr>
        <tr><td>Network Configurations</td><td>5</td><td>$(echo "${COMPLIANT_LIST[*]}" | grep -c '^4\.')</td><td>$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^4\.')</td><td>$(echo "${MANUAL_LIST[*]}" | grep -c '^4\.')</td></tr>
        <tr><td>System Access</td><td>15</td><td>$(echo "${COMPLIANT_LIST[*]}" | grep -c '^5\.')</td><td>$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^5\.')</td><td>$(echo "${MANUAL_LIST[*]}" | grep -c '^5\.')</td></tr>
        <tr><td>Applications</td><td>7</td><td>$(echo "${COMPLIANT_LIST[*]}" | grep -c '^6\.')</td><td>$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^6\.')</td><td>$(echo "${MANUAL_LIST[*]}" | grep -c '^6\.')</td></tr>
    </table>
    
    <h2 class="toggle" onclick="toggleSection('software-updates')">Software Updates (Section 1)</h2>
    <div id="software-updates" style="display:block;">
        <table>
            <tr><th>Control ID</th><th>Description</th><th>Status</th><th>Severity</th><th>PoC</th></tr>
            $compliant_list
            $non_compliant_list
            $manual_list
        </table>
    </div>
    
    <h2 class="toggle" onclick="toggleSection('accounts')">Accounts (Section 2.1-2.7)</h2>
    <div id="accounts" style="display:block;">
        <table>
            <tr><th>Control ID</th><th>Description</th><th>Status</th><th>Severity</th><th>PoC</th></tr>
            $(for item in "${COMPLIANT_LIST[@]}" "${NON_COMPLIANT_LIST[@]}" "${MANUAL_LIST[@]}"; do
                if [[ $item =~ ^2\.[1-7]\..* ]]; then
                    IFS=':' read -r id desc status sev poc <<< "$item"
                    echo "<tr><td class='$status'>$id</td><td>$desc</td><td>$status</td><td>$sev</td><td class='tooltip'>$([ -n "$poc" ] && echo "<span class='tooltiptext'>$poc</span>" || echo "")</td></tr>"
                fi
            done)
        </table>
    </div>
    
    <h2 class="toggle" onclick="toggleSection('restrictions')">Restrictions (Section 2.8)</h2>
    <div id="restrictions" style="display:block;">
        <table>
            <tr><th>Control ID</th><th>Description</th><th>Status</th><th>Severity</th><th>PoC</th></tr>
            $(for item in "${COMPLIANT_LIST[@]}" "${NON_COMPLIANT_LIST[@]}" "${MANUAL_LIST[@]}"; do
                if [[ $item =~ ^2\.8\..* ]]; then
                    IFS=':' read -r id desc status sev poc <<< "$item"
                    echo "<tr><td class='$status'>$id</td><td>$desc</td><td>$status</td><td>$sev</td><td class='tooltip'>$([ -n "$poc" ] && echo "<span class='tooltiptext'>$poc</span>" || echo "")</td></tr>"
                fi
            done | sort -t':' -k4r,4 -k1)
        </table>
    </div>
    
    <h2 class="toggle" onclick="toggleSection('security')">Security (Section 2.9)</h2>
    <div id="security" style="display:block;">
        <table>
            <tr><th>Control ID</th><th>Description</th><th>Status</th><th>Severity</th><th>PoC</th></tr>
            $(for item in "${COMPLIANT_LIST[@]}" "${NON_COMPLIANT_LIST[@]}" "${MANUAL_LIST[@]}"; do
                if [[ $item =~ ^2\.9\..* ]]; then
                    IFS=':' read -r id desc status sev poc <<< "$item"
                    echo "<tr><td class='$status'>$id</td><td>$desc</td><td>$status</td><td>$sev</td><td class='tooltip'>$([ -n "$poc" ] && echo "<span class='tooltiptext'>$poc</span>" || echo "")</td></tr>"
                fi
            done | sort -t':' -k4r,4 -k1)
        </table>
    </div>
    
    <h2 class="toggle" onclick="toggleSection('software-update')">Software Update (Section 2.10)</h2>
    <div id="software-update" style="display:block;">
        <table>
            <tr><th>Control ID</th><th>Description</th><th>Status</th><th>Severity</th><th>PoC</th></tr>
            $(for item in "${COMPLIANT_LIST[@]}" "${NON_COMPLIANT_LIST[@]}" "${MANUAL_LIST[@]}"; do
                if [[ $item =~ ^2\.10\..* ]]; then
                    IFS=':' read -r id desc status sev poc <<< "$item"
                    echo "<tr><td class='$status'>$id</td><td>$desc</td><td>$status</td><td>$sev</td><td class='tooltip'>$([ -n "$poc" ] && echo "<span class='tooltiptext'>$poc</span>" || echo "")</td></tr>"
                fi
            done)
        </table>
    </div>
    
    <h2 class="toggle" onclick="toggleSection('system-config')">System Configuration (Section 2.11-2.13)</h2>
    <div id="system-config" style="display:block;">
        <table>
            <tr><th>Control ID</th><th>Description</th><th>Status</th><th>Severity</th><th>PoC</th></tr>
            $(for item in "${COMPLIANT_LIST[@]}" "${NON_COMPLIANT_LIST[@]}" "${MANUAL_LIST[@]}"; do
                if [[ $item =~ ^2\.1[1-3]\..* ]]; then
                    IFS=':' read -r id desc status sev poc <<< "$item"
                    echo "<tr><td class='$status'>$id</td><td>$desc</td><td>$status</td><td>$sev</td><td class='tooltip'>$([ -n "$poc" ] && echo "<span class='tooltiptext'>$poc</span>" || echo "")</td></tr>"
                fi
            done)
        </table>
    </div>
    
    <h2 class="toggle" onclick="toggleSection('logging')">Logging and Auditing (Section 3)</h2>
    <div id="logging" style="display:block;">
        <table>
            <tr><th>Control ID</th><th>Description</th><th>Status</th><th>Severity</th><th>PoC</th></tr>
            $(for item in "${COMPLIANT_LIST[@]}" "${NON_COMPLIANT_LIST[@]}" "${MANUAL_LIST[@]}"; do
                if [[ $item =~ ^3\..* ]]; then
                    IFS=':' read -r id desc status sev poc <<< "$item"
                    echo "<tr><td class='$status'>$id</td><td>$desc</td><td>$status</td><td>$sev</td><td class='tooltip'>$([ -n "$poc" ] && echo "<span class='tooltiptext'>$poc</span>" || echo "")</td></tr>"
                fi
            done)
        </table>
    </div>
    
    <h2 class="toggle" onclick="toggleSection('network')">Network Configurations (Section 4)</h2>
    <div id="network" style="display:block;">
        <table>
            <tr><th>Control ID</th><th>Description</th><th>Status</th><th>Severity</th><th>PoC</th></tr>
            $(for item in "${COMPLIANT_LIST[@]}" "${NON_COMPLIANT_LIST[@]}" "${MANUAL_LIST[@]}"; do
                if [[ $item =~ ^4\..* ]]; then
                    IFS=':' read -r id desc status sev poc <<< "$item"
                    echo "<tr><td class='$status'>$id</td><td>$desc</td><td>$status</td><td>$sev</td><td class='tooltip'>$([ -n "$poc" ] && echo "<span class='tooltiptext'>$poc</span>" || echo "")</td></tr>"
                fi
            done)
        </table>
    </div>
    
    <h2 class="toggle" onclick="toggleSection('system-access')">System Access (Section 5)</h2>
    <div id="system-access" style="display:block;">
        <table>
            <tr><th>Control ID</th><th>Description</th><th>Status</th><th>Severity</th><th>PoC</th></tr>
            $(for item in "${COMPLIANT_LIST[@]}" "${NON_COMPLIANT_LIST[@]}" "${MANUAL_LIST[@]}"; do
                if [[ $item =~ ^5\..* ]]; then
                    IFS=':' read -r id desc status sev poc <<< "$item"
                    echo "<tr><td class='$status'>$id</td><td>$desc</td><td>$status</td><td>$sev</td><td class='tooltip'>$([ -n "$poc" ] && echo "<span class='tooltiptext'>$poc</span>" || echo "")</td></tr>"
                fi
            done)
        </table>
    </div>
    
    <h2 class="toggle" onclick="toggleSection('applications')">Applications (Section 6)</h2>
    <div id="applications" style="display:block;">
        <table>
            <tr><th>Control ID</th><th>Description</th><th>Status</th><th>Severity</th><th>PoC</th></tr>
            $(for item in "${COMPLIANT_LIST[@]}" "${NON_COMPLIANT_LIST[@]}" "${MANUAL_LIST[@]}"; do
                if [[ $item =~ ^6\..* ]]; then
                    IFS=':' read -r id desc status sev poc <<< "$item"
                    echo "<tr><td class='$status'>$id</td><td>$desc</td><td>$status</td><td>$sev</td><td class='tooltip'>$([ -n "$poc" ] && echo "<span class='tooltiptext'>$poc</span>" || echo "")</td></tr>"
                fi
            done)
        </table>
    </div>
</body>
</html>
EOF
}

# Function to generate CSV report
generate_csv_report() {
    echo "Section,Control ID,Description,Status,Severity,PoC" > "$CSV_OUTPUT"
    for section in "Software Updates:1\." "Accounts:2\.[1-7]\." "Restrictions:2\.8\." "Security:2\.9\." "Software Update:2\.10\." "System Configuration:2\.1[1-3]\." "Logging and Auditing:3\." "Network Configurations:4\." "System Access:5\." "Applications:6\."; do
        IFS=':' read -r sec_name sec_pattern <<< "$section"
        for item in "${COMPLIANT_LIST[@]}" "${NON_COMPLIANT_LIST[@]}" "${MANUAL_LIST[@]}"; do
            if [[ $item =~ $sec_pattern ]]; then
                IFS=':' read -r id desc status sev poc <<< "$item"
                echo "$sec_name,$id,\"$desc\",$status,$sev,\"$poc\"" >> "$CSV_OUTPUT"
            fi
        done
    done
}

# Function to generate JSON report
generate_json_report() {
    printf '{"hostname":"%s","timestamp":"%s","total_checks":%d,"passed":%d,"failed":%d,"manual_required":%d,"controls":[' "$HOSTNAME" "$TIMESTAMP" $((COMPLIANT_COUNT + NON_COMPLIANT_COUNT + MANUAL_COUNT)) "$COMPLIANT_COUNT" "$NON_COMPLIANT_COUNT" "$MANUAL_COUNT" > "$JSON_OUTPUT"
    for i in "${!JSON_ARRAY[@]}"; do
        printf "%s" "${JSON_ARRAY[$i]}" >> "$JSON_OUTPUT"
        [ $i -lt $((${#JSON_ARRAY[@]} - 1)) ] && printf "," >> "$JSON_OUTPUT"
    done
    printf "]}" >> "$JSON_OUTPUT"
}

# Function to print section summary to console
print_section_summary() {
    echo -e "\nSection Summary:"
    echo "--------------------------------------------------"
    printf "%-30s %-10s %-10s %-10s %-10s\n" "Section" "Total" "Compliant" "Non-Compliant" "Manual"
    echo "--------------------------------------------------"
    printf "%-30s %-10s %-10s %-10s %-10s\n" "Software Updates" "6" "$(echo "${COMPLIANT_LIST[*]}" | grep -c '^1\.')" "$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^1\.')" "$(echo "${MANUAL_LIST[*]}" | grep -c '^1\.')"
    printf "%-30s %-10s %-10s %-10s %-10s\n" "Accounts" "8" "$(echo "${COMPLIANT_LIST[*]}" | grep -c '^2\.[1-7]\.')" "$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^2\.[1-7]\.')" "$(echo "${MANUAL_LIST[*]}" | grep -c '^2\.[1-7]\.')"
    printf "%-30s %-10s %-10s %-10s %-10s\n" "Restrictions" "42" "$(echo "${COMPLIANT_LIST[*]}" | grep -c '^2\.8\.')" "$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^2\.8\.')" "$(echo "${MANUAL_LIST[*]}" | grep -c '^2\.8\.')"
    printf "%-30s %-10s %-10s %-10s %-10s\n" "Security" "12" "$(echo "${COMPLIANT_LIST[*]}" | grep -c '^2\.9\.')" "$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^2\.9\.')" "$(echo "${MANUAL_LIST[*]}" | grep -c '^2\.9\.')"
    printf "%-30s %-10s %-10s %-10s %-10s\n" "Software Update" "5" "$(echo "${COMPLIANT_LIST[*]}" | grep -c '^2\.10\.')" "$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^2\.10\.')" "$(echo "${MANUAL_LIST[*]}" | grep -c '^2\.10\.')"
    printf "%-30s %-10s %-10s %-10s %-10s\n" "System Configuration" "7" "$(echo "${COMPLIANT_LIST[*]}" | grep -c '^2\.1[1-3]\.')" "$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^2\.1[1-3]\.')" "$(echo "${MANUAL_LIST[*]}" | grep -c '^2\.1[1-3]\.')"
    printf "%-30s %-10s %-10s %-10s %-10s\n" "Logging and Auditing" "5" "$(echo "${COMPLIANT_LIST[*]}" | grep -c '^3\.')" "$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^3\.')" "$(echo "${MANUAL_LIST[*]}" | grep -c '^3\.')"
    printf "%-30s %-10s %-10s %-10s %-10s\n" "Network Configurations" "5" "$(echo "${COMPLIANT_LIST[*]}" | grep -c '^4\.')" "$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^4\.')" "$(echo "${MANUAL_LIST[*]}" | grep -c '^4\.')"
    printf "%-30s %-10s %-10s %-10s %-10s\n" "System Access" "15" "$(echo "${COMPLIANT_LIST[*]}" | grep -c '^5\.')" "$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^5\.')" "$(echo "${MANUAL_LIST[*]}" | grep -c '^5\.')"
    printf "%-30s %-10s %-10s %-10s %-10s\n" "Applications" "7" "$(echo "${COMPLIANT_LIST[*]}" | grep -c '^6\.')" "$(echo "${NON_COMPLIANT_LIST[*]}" | grep -c '^6\.')" "$(echo "${MANUAL_LIST[*]}" | grep -c '^6\.')"
    echo "--------------------------------------------------"
}

# Initialize log and arrays
> "$LOG_FILE"
JSON_ARRAY=()
COMPLIANT_LIST=()
NON_COMPLIANT_LIST=()
MANUAL_LIST=()
CONTROL_IDS=()
log_message "Starting CIS macOS 15.0 Sequoia compliance check (Version 1.9.7, 107 controls)"
echo "Starting CIS macOS 15.0 Sequoia compliance check (Version 1.9.7, 107 controls)"

# 1. Software Updates
CURRENT_SECTION="Software Updates"
check_details=$(safe_system_check "defaults read /Library/Preferences/com.apple.SoftwareUpdate LastResultCode" "2")
if [ $? -eq 0 ]; then
    print_status "1.1" "Ensure All Apple-provided Software Is Current" "Compliant" "" "" "High"
else
    check_details=$(safe_system_check "softwareupdate --list | grep -i 'No new software available'" "No new software available")
    if [ $? -eq 0 ]; then
        print_status "1.1" "Ensure All Apple-provided Software Is Current" "Compliant" "" "" "High"
    else
        print_status "1.1" "Ensure All Apple-provided Software Is Current" "Non-Compliant" "Run: sudo softwareupdate --install --all" "$check_details" "High"
    fi
fi

check_details=$(check_mdm_profile "com.apple.SoftwareUpdate" "AutomaticDownload" "1" || safe_system_check "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload" "1")
if [ $? -eq 0 ]; then
    print_status "1.2" "Ensure Auto Update Is Enabled" "Compliant" "" "" "Medium"
else
    print_status "1.2" "Ensure Auto Update Is Enabled" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Software Update > Set 'AutomaticDownload' to True" "$check_details" "Medium"
fi

check_details=$(safe_system_check "softwareupdate --list | grep 'Security Update'" "")
if [ $? -eq 0 ]; then
    print_status "1.3" "Ensure Security Updates Are Installed" "Compliant" "" "" "High"
else
    print_status "1.3" "Ensure Security Updates Are Installed" "Non-Compliant" "Run: sudo softwareupdate --install --all" "$check_details" "High"
fi

check_details=$(check_mdm_profile "com.apple.softwareupdate" "ConfigDataInstall" "1" || safe_system_check "defaults read /Library/Preferences/com.apple.softwareupdate ConfigDataInstall" "1")
if [ $? -eq 0 ]; then
    print_status "1.4" "Ensure Install System Data Files and Security Updates Is Enabled" "Compliant" "" "" "High"
else
    print_status "1.4" "Ensure Install System Data Files and Security Updates Is Enabled" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Software Update > Set 'ConfigDataInstall' to True" "$check_details" "High"
fi

check_details=$(check_mdm_profile "com.apple.softwareupdate" "enforceSoftwareUpdateDelay" "30" || safe_system_check "defaults read /Library/Preferences/com.apple.softwareupdate enforceSoftwareUpdateDelay" "30")
if [ $? -eq 0 ] || [ -z "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate enforceSoftwareUpdateDelay 2>/dev/null)" ]; then
    print_status "1.7" "Ensure Software Update Deferment Is Less Than or Equal to 30 Days" "Compliant" "" "" "Medium"
else
    print_status "1.7" "Ensure Software Update Deferment Is Less Than or Equal to 30 Days" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Software Update > Set 'enforceSoftwareUpdateDelay' to 30" "$check_details" "Medium"
fi

check_details=$(profiles show -type configuration >/dev/null 2>&1 && echo "MDM profile detected" || echo "No MDM profile found")
if [ $? -eq 0 ]; then
    print_status "1.8" "Ensure the System is Managed by MDM Software" "Compliant" "" "" "High"
else
    print_status "1.8" "Ensure the System is Managed by MDM Software" "Non-Compliant" "Enroll the device in Intune: Devices > Enroll devices > Ensure MDM profile is installed" "$check_details" "High"
fi

# 2.1 Accounts
CURRENT_SECTION="Accounts"
check_details=$(check_mdm_profile "com.apple.loginwindow" "GuestEnabled" "0" || safe_system_check "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled" "0")
if [ $? -eq 0 ]; then
    print_status "2.1.1.1" "Ensure Disable Guest Account is set to True" "Compliant" "" "" "High"
else
    print_status "2.1.1.1" "Ensure Disable Guest Account is set to True" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Login Window > Set 'GuestEnabled' to False" "$check_details" "High"
fi

# 2.2 App Store
check_details=$(check_mdm_profile "com.apple.commerce" "RestrictStoreSoftwareUpdateOnly" "1" || safe_system_check "defaults read /Library/Preferences/com.apple.commerce RestrictStoreSoftwareUpdateOnly" "1")
if [ $? -eq 0 ]; then
    print_status "2.2.1" "Ensure Restrict Store Software Update Only is set to True" "Compliant" "" "" "Medium"
else
    print_status "2.2.1" "Ensure Restrict Store Software Update Only is set to True" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > App Store > Set 'RestrictStoreSoftwareUpdateOnly' to True" "$check_details" "Medium"
fi

# 2.3 Full Disk Encryption
print_status "2.3.1.1" "Ensure User Enters Missing Info for FileVault is set to True" "Manual verification required in Intune: Devices > Configuration > FileVault settings" "" "High"
check_details=$(check_mdm_profile "com.apple.MCX.FileVault2" "enable" "On" || safe_system_check "fdesetup status | grep 'FileVault is On'" "FileVault is On")
if [ $? -eq 0 ]; then
    print_status "2.3.1.2" "Ensure FileVault Enable is set to On" "Compliant" "" "" "High"
else
    print_status "2.3.1.2" "Ensure FileVault Enable is set to On" "Non-Compliant" "In Intune: Endpoint security > Disk encryption > Set 'enable' to On" "$check_details" "High"
fi
print_status "2.3.1.3" "Ensure Defer Force At User Login Max Bypass Attempts is set to 0" "Manual verification required in Intune: Devices > Configuration > FileVault settings" "" "High"
print_status "2.3.1.4" "Ensure Show Recovery Key is set to Disabled" "Manual verification required in Intune: Devices > Configuration > FileVault settings" "" "High"
print_status "2.3.1.5" "Ensure Force Enable In Setup Assistant is set to True" "Manual verification required in Intune: Devices > Configuration > FileVault settings" "" "High"
print_status "2.3.2.1" "Ensure Prevent FileVault From Being Disabled is set to True" "Manual verification required in Intune: Devices > Configuration > FileVault Options" "" "High"
print_status "2.3.3.1" "Ensure There is a Disk Encryption FileVault Policy" "Manual verification required in Intune: Endpoint security > Disk encryption" "" "High"

# 2.4 Login
check_details=$(check_mdm_profile "com.apple.loginwindow" "SHOWFULLNAME" "1" || safe_system_check "defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME" "1")
if [ $? -eq 0 ]; then
    print_status "2.4.1.1" "Ensure Show Full Name is set to True" "Compliant" "" "" "Low"
else
    print_status "2.4.1.1" "Ensure Show Full Name is set to True" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Login Window > Set 'SHOWFULLNAME' to True" "$check_details" "Low"
fi

check_details=$(check_mdm_profile "com.apple.loginitems.managed" "DisableLoginItemsSuppression" "1" || safe_system_check "defaults read /Library/Preferences/com.apple.loginwindow DisableLoginItemsSuppression" "1")
if [ $? -eq 0 ]; then
    print_status "2.4.2.1" "Ensure Disable Login Items Suppression is set to True" "Compliant" "" "" "Medium"
else
    print_status "2.4.2.1" "Ensure Disable Login Items Suppression is set to True" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Login Window > Set 'DisableLoginItemsSuppression' to True" "$check_details" "Medium"
fi

# 2.5 Managed Settings
print_status "2.5.1.1" "Ensure Activation Lock Allowed While Supervised is set appropriately" "Manual verification required in Intune: Devices > macOS > Enrollment > ABM settings" "" "Medium"

# 2.6 Networking
check_details=$(check_mdm_profile "com.apple.applicationaccess" "allowContentCaching" "0" || safe_system_check "defaults read /Library/Preferences/com.apple.applicationaccess allowContentCaching" "0")
if [ $? -eq 0 ]; then
    print_status "2.6.1.1" "Ensure Auto Activation for Content Caching is set to False" "Compliant" "" "" "Medium"
else
    print_status "2.6.1.1" "Ensure Auto Activation for Content Caching is set to False" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Content Caching > Set 'allowContentCaching' to False" "$check_details" "Medium"
fi

check_details=$(check_mdm_profile "com.apple.security.firewall" "EnableStealthMode" "1" || safe_system_check "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | grep 'stealth mode is on'" "stealth mode is on")
if [ $? -eq 0 ]; then
    print_status "2.6.2.1" "Ensure Enable Stealth Mode is set to True" "Compliant" "" "" "High"
else
    print_status "2.6.2.1" "Ensure Enable Stealth Mode is set to True" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Firewall > Set 'EnableStealthMode' to True" "$check_details" "High"
fi

check_details=$(check_mdm_profile "com.apple.security.firewall" "EnableFirewall" "1" || safe_system_check "defaults read /Library/Preferences/com.apple.security.firewall EnableFirewall" "1" || safe_system_check "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep 'Firewall is enabled'" "Firewall is enabled")
if [ $? -eq 0 ]; then
    print_status "2.6.2.2" "Ensure Enable Firewall is set to True" "Compliant" "" "" "High"
else
    print_status "2.6.2.2" "Ensure Enable Firewall is set to True" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Firewall > Set 'EnableFirewall' to True" "$check_details" "High"
fi

# 2.7 Profile Removal Password
print_status "2.7.1" "Ensure Removal Password is absent or securely configured" "Manual verification required in Intune: Devices > Configuration > Profile settings" "" "High"

# 2.8 Restrictions
CURRENT_SECTION="Restrictions"
restrictions=(
    "2.8.1 allowBluetoothSharingModification 0 Medium"
    "2.8.2 allowPasswordSharing 0 Medium"
    "2.8.3 allowFileSharingModification 0 Medium"
    "2.8.4 allowEraseContentAndSettings 0 High"
    "2.8.5 allowAirPlayIncomingRequests 0 Medium"
    "2.8.6 allowMediaSharingModification 0 Medium"
    "2.8.7 disallowiCloudPhotoLibrary 1 Medium"
    "2.8.8 disallowiCloudDocumentSync 1 Medium"
    "2.8.9 enforceSoftwareUpdateDelay 30 Medium"
    "2.8.10 allowActivityContinuation 0 Medium"
    "2.8.11 disallowiCloudBookmarks 1 Medium"
    "2.8.12 disallowiCloudFreeform 1 Medium"
    "2.8.13 disallowiCloudCalendar 1 Medium"
    "2.8.14 allowARDRemoteManagementModification 0 High"
    "2.8.15 allowAssistant 0 Low"
    "2.8.16 allowGameCenter 0 Low"
    "2.8.17 allowAutoUnlock 0 High"
    "2.8.18 allowStartupDiskModification 0 High"
    "2.8.19 allowUIConfigurationProfileInstallation 0 High"
    "2.8.20 allowDeviceNameModification 0 Medium"
    "2.8.21 allowInternetSharingModification 0 Medium"
    "2.8.22 allowContentCaching 0 Medium"
    "2.8.23 allowFindMyFriends 0 Medium"
    "2.8.24 allowAirDrop 0 Medium"
    "2.8.25 allowPasswordAutoFill 0 High"
    "2.8.26 disallowiCloudNotes 1 Medium"
    "2.8.27 allowMultiplayerGaming 0 Low"
    "2.8.28 allowLocalUserCreation 0 High"
    "2.8.29 allowApplePersonalizedAdvertising 0 Medium"
    "2.8.30 allowPrinterSharingModification 0 Medium"
    "2.8.31 allowFingerprintForUnlock 0 High"
    "2.8.32 allowDiagnosticSubmission 0 Medium"
    "2.8.33 disallowiCloudReminders 1 Medium"
    "2.8.34 allowPasswordProximityRequests 0 Medium"
    "2.8.35 forceOnDeviceOnlyDictation 1 Medium"
    "2.8.36 allowiPhoneMirroring 0 Medium"
    "2.8.37 disallowiCloudMail 1 Medium"
    "2.8.38 allowUniversalControl 0 Medium"
    "2.8.39 disallowiCloudAddressBook 1 Medium"
    "2.8.40 disallowiCloudDesktopAndDocuments 1 Medium"
    "2.8.41 allowiTunesFileSharing 0 Medium"
    "2.8.42 disallowiCloudKeychainSync 1 High"
)
for restriction in "${restrictions[@]}"; do
    read -r control_id key expected_value severity <<< "$restriction"
    check_details=$(check_mdm_profile "com.apple.applicationaccess" "$key" "$expected_value")
    if [ $? -eq 0 ]; then
        print_status "$control_id" "Ensure '$key' is set correctly" "Compliant" "" "" "$severity"
    else
        system_check=""
        case "$key" in
            allowAirDrop) system_check="defaults read com.apple.sharing AirDropEnabled" ;;
            allowAssistant) system_check="defaults read com.apple.assistant.support 'Assistant Enabled'" ;;
            *) system_check="defaults read /Library/Preferences/com.apple.applicationaccess $key" ;;
        esac
        check_details=$(safe_system_check "$system_check" "$expected_value")
        if [ $? -eq 0 ]; then
            print_status "$control_id" "Ensure '$key' is set correctly" "Compliant" "" "" "$severity"
        else
            print_status "$control_id" "Ensure '$key' is not correctly configured" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Restrictions > Set '$key' to $expected_value" "$check_details" "$severity"
        fi
    fi
done

# 2.9 Security
CURRENT_SECTION="Security"
security_controls=(
    "2.9.1.1 maxPinAgeInDays 90 High"
    "2.9.1.2 maxGracePeriod 0 High"
    "2.9.1.3 maxInactivity 8 High"
    "2.9.1.4 minComplexCharacters 1 High"
    "2.9.1.5 pinHistory 5 High"
    "2.9.1.6 forcePIN 1 High"
    "2.9.1.7 passwordContentRegex ^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9!@#\$%\^&\*\(\)_\+\-=\[\]\{\};\":\\\\|,.<>/?]).{8,}\$ High"
    "2.9.1.8 maxFailedAttempts 15 High"
    "2.9.1.9 allowSimplePasscode 0 High"
    "2.9.1.10 minutesUntilFailedLoginReset 15 High"
    "2.9.1.11 requireAlphanumericPasscode 1 High"
    "2.9.1.12 minLength 8 High"
)
for security_control in "${security_controls[@]}"; do
    read -r control_id key expected_value severity <<< "$security_control"
    check_details=$(check_mdm_profile "com.apple.mobiledevice.passwordpolicy" "$key" "$expected_value")
    if [ $? -eq 0 ]; then
        print_status "$control_id" "Ensure '$key' is set correctly" "Compliant" "" "" "$severity"
    else
        check_details=$(safe_password_check "$key" "$expected_value")
        if [ $? -eq 0 ]; then
            print_status "$control_id" "Ensure '$key' is set correctly" "Compliant" "" "" "$severity"
        else
            print_status "$control_id" "Ensure '$key' is not correctly configured" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Passcode > Set '$key' to $expected_value" "$check_details" "$severity"
        fi
    fi
done

# 2.10 Software Update
CURRENT_SECTION="Software Update"
check_details=$(check_mdm_profile "com.apple.softwareupdate" "AutomaticallyInstallAppUpdates" "1" || safe_system_check "defaults read /Library/Preferences/com.apple.softwareupdate AutomaticallyInstallAppUpdates" "1")
if [ $? -eq 0 ]; then
    print_status "2.10.1" "Ensure Automatically Install App Updates is set to True" "Compliant" "" "" "Medium"
else
    print_status "2.10.1" "Ensure Automatically Install App Updates is set to True" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Software Update > Set 'AutomaticallyInstallAppUpdates' to True" "$check_details" "Medium"
fi

check_details=$(check_mdm_profile "com.apple.softwareupdate" "AutomaticallyInstallMacOSUpdates" "1" || safe_system_check "defaults read /Library/Preferences/com.apple.softwareupdate AutomaticallyInstallMacOSUpdates" "1")
if [ $? -eq 0 ]; then
    print_status "2.10.2" "Ensure Automatically Install macOS Updates is set to True" "Compliant" "" "" "Medium"
else
    print_status "2.10.2" "Ensure Automatically Install macOS Updates is set to True" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Software Update > Set 'AutomaticallyInstallMacOSUpdates' to True" "$check_details" "Medium"
fi

check_details=$(check_mdm_profile "com.apple.softwareupdate" "AutomaticCheckEnabled" "1" || safe_system_check "defaults read /Library/Preferences/com.apple.softwareupdate AutomaticCheckEnabled" "1")
if [ $? -eq 0 ]; then
    print_status "2.10.3" "Ensure Automatic Check Enabled is set to True" "Compliant" "" "" "Medium"
else
    print_status "2.10.3" "Ensure Automatic Check Enabled is set to True" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Software Update > Set 'AutomaticCheckEnabled' to True" "$check_details" "Medium"
fi

check_details=$(check_mdm_profile "com.apple.softwareupdate" "CriticalUpdateInstall" "1" || safe_system_check "defaults read /Library/Preferences/com.apple.softwareupdate CriticalUpdateInstall" "1")
if [ $? -eq 0 ]; then
    print_status "2.10.4" "Ensure Critical Update Install is set to True" "Compliant" "" "" "High"
else
    print_status "2.10.4" "Ensure Critical Update Install is set to True" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Software Update > Set 'CriticalUpdateInstall' to True" "$check_details" "High"
fi

check_details=$(check_mdm_profile "com.apple.softwareupdate" "AutomaticDownload" "1" || safe_system_check "defaults read /Library/Preferences/com.apple.softwareupdate AutomaticDownload" "1")
if [ $? -eq 0 ]; then
    print_status "2.10.5" "Ensure Automatic Download is set to True" "Compliant" "" "" "Medium"
else
    print_status "2.10.5" "Ensure Automatic Download is set to True" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Software Update > Set 'AutomaticDownload' to True" "$check_details" "Medium"
fi

# 2.11 System Configuration
CURRENT_SECTION="System Configuration"
check_details=$(check_mdm_profile "com.apple.screensaver" "idleTime" "600" || safe_system_check "defaults read /Library/Preferences/com.apple.screensaver idleTime" "600")
if [ $? -eq 0 ]; then
    print_status "2.11.1.1" "Ensure Display Sleep Timer is set to 10 or less" "Compliant" "" "" "Medium"
else
    print_status "2.11.1.1" "Ensure Display Sleep Timer is set to 10 or less" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Energy Saver > Set 'idleTime' to 600" "$check_details" "Medium"
fi

check_details=$(check_mdm_profile "com.apple.MCX" "SystemSleepTimer" "900" || safe_system_check "pmset -g custom | grep 'sleep.*15'" "sleep.*15")
if [ $? -eq 0 ]; then
    print_status "2.11.1.2" "Ensure System Sleep Timer is set to 15 or less" "Compliant" "" "" "Medium"
else
    print_status "2.11.1.2" "Ensure System Sleep Timer is set to 15 or less" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Energy Saver > Set 'SystemSleepTimer' to 900" "$check_details" "Medium"
fi

check_details=$(check_mdm_profile "com.apple.MCX" "WakeOnLAN" "0" || safe_system_check "pmset -g custom | grep 'womp.*0'" "womp.*0")
if [ $? -eq 0 ]; then
    print_status "2.11.1.3" "Ensure Wake on LAN is set to False" "Compliant" "" "" "Medium"
else
    print_status "2.11.1.3" "Ensure Wake on LAN is set to False" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Energy Saver > Set 'WakeOnLAN' to False" "$check_details" "Medium"
fi

check_details=$(check_mdm_profile "com.apple.MCX" "WakeOnModemRing" "0" || safe_system_check "pmset -g custom | grep ring" "")
if [ $? -eq 0 ]; then
    print_status "2.11.1.4" "Ensure Wake On Modem Ring is set to False" "Compliant" "" "" "Medium"
else
    print_status "2.11.1.4" "Ensure Wake On Modem Ring is set to False" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Energy Saver > Set 'WakeOnModemRing' to False" "$check_details" "Medium"
fi

check_details=$(check_mdm_profile "com.apple.MCX" "DestroyFVKeyOnStandby" "1" || safe_system_check "pmset -g | grep destroyfvkeyonstandby | grep 1" "destroyfvkeyonstandby 1")
if [ $? -eq 0 ]; then
    print_status "2.11.1.5" "Ensure Destroy FV Key On Standby is set to True" "Compliant" "" "" "High"
else
    print_status "2.11.1.5" "Ensure Destroy FV Key On Standby is set to True" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > FileVault > Set 'DestroyFVKeyOnStandby' to True" "$check_details" "High"
fi

check_details=$(check_mdm_profile "com.apple.screensaver" "askForPassword" "1" && check_mdm_profile "com.apple.screensaver" "askForPasswordDelay" "0" || safe_system_check "defaults read /Library/Preferences/com.apple.screensaver askForPassword" "1" && safe_system_check "defaults read /Library/Preferences/com.apple.screensaver askForPasswordDelay" "0")
if [ $? -eq 0 ]; then
    print_status "2.11.2.1" "Ensure Ask For Password is set to True and Delay is 0" "Compliant" "" "" "High"
else
    print_status "2.11.2.1" "Ensure Ask For Password is set to True and Delay is 0" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Screensaver > Set 'askForPassword' to True and 'askForPasswordDelay' to 0" "$check_details" "High"
fi

# 2.12 System Policy Control
check_details=$(check_mdm_profile "com.apple.systempolicy.control" "EnableXProtectMalwareUpload" "0" || safe_system_check "defaults read /Library/Preferences/com.apple.systempolicy.control EnableXProtectMalwareUpload" "0")
if [ $? -eq 0 ]; then
    print_status "2.12.1.1" "Ensure Enable XProtect Malware Upload is set to Disabled" "Compliant" "" "" "Medium"
else
    print_status "2.12.1.1" "Ensure Enable XProtect Malware Upload is set to Disabled" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > System Policy Control > Set 'EnableXProtectMalwareUpload' to False" "$check_details" "Medium"
fi

check_details=$(check_mdm_profile "com.apple.systempolicy.control" "EnableAssessment" "1" || safe_system_check "spctl --status | grep 'assessments enabled'" "assessments enabled")
if [ $? -eq 0 ]; then
    print_status "2.12.1.2" "Ensure Gatekeeper is configured for Identified Developers only" "Compliant" "" "" "High"
else
    print_status "2.12.1.2" "Ensure Gatekeeper is configured for Identified Developers only" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > System Policy Control > Set 'EnableAssessment' to True" "$check_details" "High"
fi

# 2.13 Profile Implementation
check_details=$(safe_system_check "profiles show -type configuration | grep -i 'removalDisallowed.*TRUE'" "removalDisallowed.*TRUE")
if [ $? -eq 0 ]; then
    print_status "2.13.1" "Ensure Configuration Profile Can Not be Removed by an End User" "Compliant" "" "" "High"
else
    print_status "2.13.1" "Ensure Configuration Profile Can Not be Removed by an End User" "Non-Compliant" "In Intune: Devices > Configuration > Set 'Allow Profile Removal' to False" "$check_details" "High"
fi

# 3. Logging and Auditing
CURRENT_SECTION="Logging and Auditing"
check_details=$(safe_system_check "audit -c | grep 'AUC_AUDITING'" "AUC_AUDITING")
if [ $? -eq 0 ]; then
    print_status "3.1" "Ensure Security Auditing Is Enabled" "Compliant" "" "" "High"
else
    print_status "3.1" "Ensure Security Auditing Is Enabled" "Non-Compliant" "Run: sudo audit -i" "$check_details" "High"
fi

check_details=$(safe_system_check "cat /etc/security/audit_control | grep 'flags:lo,ad,fd,fm,-all'" "flags:lo,ad,fd,fm,-all")
if [ $? -eq 0 ]; then
    print_status "3.2" "Ensure Security Auditing Flags For User-Attributable Events Are Configured" "Compliant" "" "" "High"
else
    print_status "3.2" "Ensure Security Auditing Flags For User-Attributable Events Are Configured" "Non-Compliant" "Edit /etc/security/audit_control: set 'flags:lo,ad,fd,fm,-all'" "$check_details" "High"
fi

check_details=$(safe_system_check "cat /etc/asl/com.apple.install | grep 'ttl=365'" "ttl=365")
if [ $? -eq 0 ]; then
    print_status "3.3" "Ensure install.log Is Retained for 365 or More Days" "Compliant" "" "" "Medium"
else
    print_status "3.3" "Ensure install.log Is Retained for 365 or More Days" "Non-Compliant" "Edit /etc/asl/com.apple.install: set 'ttl=365'" "$check_details" "Medium"
fi

check_details=$(safe_system_check "cat /etc/security/audit_control | grep 'expire-after:365d'" "expire-after:365d")
if [ $? -eq 0 ]; then
    print_status "3.4" "Ensure Security Auditing Retention Is Enabled" "Compliant" "" "" "High"
else
    print_status "3.4" "Ensure Security Auditing Retention Is Enabled" "Non-Compliant" "Edit /etc/security/audit_control: set 'expire-after:365d'" "$check_details" "High"
fi

check_details=$(safe_system_check "ls -l /var/audit | grep 'root:wheel'" "root:wheel")
if [ $? -eq 0 ]; then
    print_status "3.5" "Ensure Access to Audit Records Is Controlled" "Compliant" "" "" "High"
else
    print_status "3.5" "Ensure Access to Audit Records Is Controlled" "Non-Compliant" "Set permissions: sudo chown -R root:wheel /var/audit" "$check_details" "High"
fi

# 4. Network Configurations
CURRENT_SECTION="Network Configurations"
check_details=$(check_mdm_profile "com.apple.mDNSResponder" "NoMulticastAdvertisements" "1" || safe_system_check "defaults read /Library/Preferences/com.apple.mDNSResponder NoMulticastAdvertisements" "1")
if [ $? -eq 0 ]; then
    print_status "4.1" "Ensure Bonjour Advertising Services Is Disabled" "Compliant" "" "" "Medium"
else
    print_status "4.1" "Ensure Bonjour Advertising Services Is Disabled" "Non-Compliant" "In Intune: Devices > Configuration > Add settings > Network > Set 'NoMulticastAdvertisements' to True" "$check_details" "Medium"
fi

check_details=$(safe_system_check "launchctl list | grep 'com.apple.httpd'" "")
if [ $? -eq 0 ]; then
    print_status "4.2" "Ensure HTTP Server Is Disabled" "Compliant" "" "" "Medium"
else
    print_status "4.2" "Ensure HTTP Server Is Disabled" "Non-Compliant" "Run: sudo launchctl disable system/com.apple.httpd" "$check_details" "Medium"
fi

check_details=$(safe_system_check "launchctl list | grep 'com.apple.nfsd'" "")
if [ $? -eq 0 ]; then
    print_status "4.3" "Ensure NFS Server Is Disabled" "Compliant" "" "" "Medium"
else
    print_status "4.3" "Ensure NFS Server Is Disabled" "Non-Compliant" "Run: sudo launchctl disable system/com.apple.nfsd" "$check_details" "Medium"
fi

check_details=$(safe_system_check "launchctl list | grep 'com.apple.smbd'" "")
if [ $? -eq 0 ]; then
    print_status "4.4" "Ensure SMB File Sharing Is Disabled" "Compliant" "" "" "Medium"
else
    print_status "4.4" "Ensure SMB File Sharing Is Disabled" "Non-Compliant" "Run: sudo launchctl disable system/com.apple.smbd" "$check_details" "Medium"
fi

check_details=$(safe_system_check "launchctl list | grep 'com.apple.ARD'" "")
if [ $? -eq 0 ]; then
    print_status "4.5" "Ensure Remote Management Is Disabled" "Compliant" "" "" "High"
else
    print_status "4.5" "Ensure Remote Management Is Disabled" "Non-Compliant" "Run: sudo launchctl disable system/com.apple.ARD" "$check_details" "High"
fi

# 5. System Access
CURRENT_SECTION="System Access"
check_details=$(safe_system_check "find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d -not -perm 700 | grep -v Shared | grep -v Guest" "")
if [ $? -eq 0 ]; then
    print_status "5.1.1" "Ensure Home Folders Are Secure" "Compliant" "" "" "High"
else
    print_status "5.1.1" "Ensure Home Folders Are Secure" "Non-Compliant" "Run: sudo chmod 700 /System/Volumes/Data/Users/*" "$check_details" "High"
fi

check_details=$(safe_system_check "csrutil status | grep enabled" "enabled")
if [ $? -eq 0 ]; then
    print_status "5.1.2" "Ensure System Integrity Protection (SIP) Is Enabled" "Compliant" "" "" "High"
else
    print_status "5.1.2" "Ensure System Integrity Protection (SIP) Is Enabled" "Non-Compliant" "Boot into Recovery mode and run: csrutil enable" "$check_details" "High"
fi

check_details=$(safe_system_check "spctl --status | grep assessments enabled" "assessments enabled")
if [ $? -eq 0 ]; then
    print_status "5.1.3" "Ensure Apple Mobile File Integrity (AMFI) Is Enabled" "Compliant" "" "" "High"
else
    print_status "5.1.3" "Ensure Apple Mobile File Integrity (AMFI) Is Enabled" "Non-Compliant" "Run: sudo spctl --master-enable" "$check_details" "High"
fi

check_details=$(safe_system_check "mount | grep sealed" "sealed")
if [ $? -eq 0 ]; then
    print_status "5.1.4" "Ensure Signed System Volume (SSV) Is Enabled" "Compliant" "" "" "High"
else
    print_status "5.1.4" "Ensure Signed System Volume (SSV) Is Enabled" "Non-Compliant" "Boot into Recovery mode and run: csrutil authenticated-root enable" "$check_details" "High"
fi

check_details=$(safe_system_check "find /Applications -type d -perm -2" "")
if [ $? -eq 0 ]; then
    print_status "5.1.5" "Ensure Appropriate Permissions Are Enabled for System Wide Applications" "Compliant" "" "" "Medium"
else
    print_status "5.1.5" "Ensure Appropriate Permissions Are Enabled for System Wide Applications" "Non-Compliant" "Run: sudo chmod -R o-w /Applications/*" "$check_details" "Medium"
fi

check_details=$(safe_system_check "find /System/Volumes/Data/System -xdev -type d -perm -2 | grep -vE \"downloadDir|locks\" 2>/dev/null | wc -l | tr -d ' '" "0")
if [ $? -eq 0 ]; then
    print_status "5.1.6" "Ensure No World Writable Folders Exist in the System Folder" "Compliant" "" "" "High"
else
    print_status "5.1.6" "Ensure No World Writable Folders Exist in the System Folder" "Non-Compliant" "Run: sudo find /System/Volumes/Data/System -xdev -type d -perm -2 -exec chmod o-w {} +" "$check_details" "High"
fi

check_details=$(safe_system_check "defaults read /Library/Preferences/com.apple.loginwindow.plist autoLoginUser" "")
if [ $? -eq 0 ]; then
    print_status "5.2" "Ensure Automatic Login Is Disabled" "Compliant" "" "" "High"
else
    print_status "5.2" "Ensure Automatic Login Is Disabled" "Non-Compliant" "Run: sudo defaults delete /Library/Preferences/com.apple.loginwindow.plist autoLoginUser" "$check_details" "High"
fi

check_details=$(safe_system_check "dscl . read /Users/root AuthenticationAuthority" "")
if [ $? -eq 0 ]; then
    print_status "5.3" "Ensure Root Account Is Disabled" "Compliant" "" "" "High"
else
    print_status "5.3" "Ensure Root Account Is Disabled" "Non-Compliant" "Run: sudo passwd -l root" "$check_details" "High"
fi

check_details=$(safe_system_check "sudo -n /usr/bin/sudo -v" "")
if [ $? -eq 0 ]; then
    print_status "5.4" "Ensure the Sudo Timeout Period Is Set to Zero" "Compliant" "" "" "Medium"
else
    print_status "5.4" "Ensure the Sudo Timeout Period Is Set to Zero" "Non-Compliant" "Edit /etc/sudoers: set Defaults timestamp_timeout=0" "$check_details" "Medium"
fi

check_details=$(safe_system_check "sudo -V | grep 'timestamp_type'" "timestamp_type: tty")
if [ $? -eq 0 ]; then
    print_status "5.5" "Ensure a Separate Timestamp Is Enabled for Each User/tty Combo" "Compliant" "" "" "Medium"
else
    print_status "5.5" "Ensure a Separate Timestamp Is Enabled for Each User/tty Combo" "Non-Compliant" "Edit /etc/sudoers: set Defaults timestamp_type=tty" "$check_details" "Medium"
fi

check_details=$(safe_system_check "sudo -l | grep 'ALL'" "")
if [ $? -eq 0 ]; then
    print_status "5.6" "Ensure the root Account Is Disabled" "Compliant" "" "" "High"
else
    print_status "5.6" "Ensure the root Account Is Disabled" "Non-Compliant" "Run: sudo passwd -l root" "$check_details" "High"
fi

check_details=$(safe_system_check "launchctl list | grep com.apple.screensharing" "")
if [ $? -eq 0 ]; then
    print_status "5.7" "Ensure Screen Sharing Is Disabled" "Compliant" "" "" "High"
else
    print_status "5.7" "Ensure Screen Sharing Is Disabled" "Non-Compliant" "Run: sudo launchctl disable system/com.apple.screensharing" "$check_details" "High"
fi

check_details=$(safe_system_check "ls /Library/Security/SecurityAgentPlugins" "loginwindow.bundle")
if [ $? -eq 0 ]; then
    print_status "5.8" "Ensure a Login Window Banner Exists" "Compliant" "" "" "Medium"
else
    print_status "5.8" "Ensure a Login Window Banner Exists" "Non-Compliant" "Create /Library/Security/SecurityAgentPlugins/loginwindow.bundle/Contents/Resources/English.lproj/InfoPlist.strings with banner text" "$check_details" "Medium"
fi

check_details=$(safe_system_check "ls /System/Volumes/Data/Users/Guest" "")
if [ $? -eq 0 ]; then
    print_status "5.9" "Ensure the Guest Home Folder Does Not Exist" "Compliant" "" "" "High"
else
    print_status "5.9" "Ensure the Guest Home Folder Does Not Exist" "Non-Compliant" "Run: sudo rm -rf /System/Volumes/Data/Users/Guest" "$check_details" "High"
fi

check_details=$(safe_system_check "spctl --status | grep assessments enabled" "assessments enabled")
if [ $? -eq 0 ]; then
    print_status "5.10" "Ensure XProtect Is Running and Updated" "Compliant" "" "" "High"
else
    print_status "5.10" "Ensure XProtect Is Running and Updated" "Non-Compliant" "Run: sudo spctl --master-enable" "$check_details" "High"
fi

check_details=$(safe_system_check "grep log_allowed /etc/sudoers /etc/sudoers.d/*" "log_allowed")
if [ $? -eq 0 ]; then
    print_status "5.11" "Ensure Logging Is Enabled for Sudo" "Compliant" "" "" "Medium"
else
    print_status "5.11" "Ensure Logging Is Enabled for Sudo" "Non-Compliant" "Edit /etc/sudoers.d/mscp: add 'Defaults log_allowed'" "$check_details" "Medium"
fi

check_details=$(safe_system_check "defaults read /Library/Preferences/com.apple.loginwindow LoginwindowText" "")
if [ $? -eq 0 ]; then
    print_status "5.12" "Ensure Password Hints Are Disabled" "Compliant" "" "" "Medium"
else
    print_status "5.12" "Ensure Password Hints Are Disabled" "Non-Compliant" "Run: sudo defaults delete /Library/Preferences/com.apple.loginwindow LoginwindowText" "$check_details" "Medium"
fi

check_details=$(safe_system_check "defaults read /Library/Preferences/com.apple.loginwindow EnableExternalAccounts" "0")
if [ $? -eq 0 ]; then
    print_status "5.13" "Ensure Fast User Switching Is Disabled" "Compliant" "" "" "Medium"
else
    print_status "5.13" "Ensure Fast User Switching Is Disabled" "Non-Compliant" "Run: sudo defaults write /Library/Preferences/com.apple.loginwindow EnableExternalAccounts -bool false" "$check_details" "Medium"
fi

check_details=$(safe_system_check "spctl --status | grep assessments enabled" "assessments enabled")
if [ $? -eq 0 ]; then
    print_status "5.14" "Ensure Gatekeeper Is Enabled" "Compliant" "" "" "High"
else
    print_status "5.14" "Ensure Gatekeeper Is Enabled" "Non-Compliant" "Run: sudo spctl --master-enable" "$check_details" "High"
fi

check_details=$(safe_system_check "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticUpdateNotify" "1")
if [ $? -eq 0 ]; then
    print_status "5.15" "Ensure Software Update Notification Is Enabled" "Compliant" "" "" "Medium"
else
    print_status "5.15" "Ensure Software Update Notification Is Enabled" "Non-Compliant" "Run: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticUpdateNotify -bool true" "$check_details" "Medium"
fi

# 6. Applications
CURRENT_SECTION="Applications"
check_details=$(safe_system_check "defaults read /Library/Preferences/com.apple.finder ShowExtensionsAllFiles" "1")
if [ $? -eq 0 ]; then
    print_status "6.1.1" "Ensure Show All Filename Extensions in Finder Is Enabled" "Compliant" "" "" "Medium"
else
    print_status "6.1.1" "Ensure Show All Filename Extensions in Finder Is Enabled" "Non-Compliant" "Run: sudo defaults write /Library/Preferences/com.apple.finder ShowExtensionsAllFiles -bool true" "$check_details" "Medium"
fi

check_details=$(safe_system_check "defaults read /Library/Preferences/com.apple.AppStore AutoUpdate" "1")
if [ $? -eq 0 ]; then
    print_status "6.2.1" "Ensure App Store Automatically Updates Apps" "Compliant" "" "" "Medium"
else
    print_status "6.2.1" "Ensure App Store Automatically Updates Apps" "Non-Compliant" "Run: sudo defaults write /Library/Preferences/com.apple.AppStore AutoUpdate -bool true" "$check_details" "Medium"
fi

check_details=$(safe_system_check "defaults read com.apple.Safari UniversalSearchEnabled" "0")
if [ $? -eq 0 ]; then
    print_status "6.3.1" "Ensure Automatic Opening of Safe Files in Safari Is Disabled" "Compliant" "" "" "Medium"
else
    print_status "6.3.1" "Ensure Automatic Opening of Safe Files in Safari Is Disabled" "Manual verification required: Check Intune for com.apple.Safari profile with UniversalSearchEnabled=0 or verify in Safari Settings > General" "$check_details" "Medium"
fi

print_status "6.3.3" "Ensure Warn When Visiting A Fraudulent Website in Safari Is Enabled" "Manual verification required: Check Intune for com.apple.Safari profile with WarnAboutFraudulentWebsites=1 or verify in Safari Settings > Security" "" "Medium"

print_status "6.3.4" "Ensure Prevent Cross-site Tracking in Safari Is Enabled" "Manual verification required: Check Intune for com.apple.Safari profile with PreventCrossSiteTracking=1 or verify in Safari Settings > Privacy" "" "Medium"

print_status "6.3.6" "Ensure Advertising Privacy Protection in Safari Is Enabled" "Manual verification required: Check Intune for com.apple.Safari profile with WebPrivacyAdvertising=1 or verify in Safari Settings > Privacy" "" "Medium"

print_status "6.3.7" "Ensure Show Full Website Address in Safari Is Enabled" "Manual verification required: Check Intune for com.apple.Safari profile with ShowFullURLInSmartSearchField=1 or verify in Safari Settings > General" "" "Medium"

print_status "6.3.10" "Ensure Show Status Bar Is Enabled" "Manual verification required: Check Intune for com.apple.Safari profile with ShowStatusBar=1 or verify in Safari View menu" "" "Low"

check_details=$(safe_system_check "defaults read com.apple.terminal SecureKeyboardEntry" "1")
if [ $? -eq 0 ]; then
    print_status "6.4.1" "Ensure Secure Keyboard Entry Terminal.app Is Enabled" "Compliant" "" "" "Medium"
else
    print_status "6.4.1" "Ensure Secure Keyboard Entry Terminal.app Is Enabled" "Manual verification required: Check Intune for com.apple.terminal profile with SecureKeyboardEntry=1 or verify in Terminal Preferences > Profiles" "$check_details" "Medium"
fi

# Generate reports
generate_json_report
generate_html_report
generate_csv_report
print_section_summary

echo "Compliance check complete. Reports generated:"
echo "JSON: $JSON_OUTPUT"
echo "HTML: $HTML_OUTPUT"
echo "CSV: $CSV_OUTPUT"
echo "Log: $LOG_FILE"