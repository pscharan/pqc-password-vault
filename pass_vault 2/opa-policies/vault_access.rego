package vault.access

# Import future keywords for compatibility
import future.keywords.if
import future.keywords.in

# Default deny all access
default allow = false
default step_up_required = false
default reason = "Access denied by default policy"

# Risk thresholds
risk_thresholds := {
    "low": 0.3,
    "medium": 0.6,
    "high": 0.8,
    "critical": 1.0
}

# High-privilege actions that require step-up authentication
high_privilege_actions := {
    "password_export",
    "vault_delete", 
    "master_password_change",
    "share_password",
    "password_delete"
}

# Actions that require biometric re-verification
critical_actions := {
    "vault_delete",
    "master_password_change",
    "password_export"
}

# Calculate device risk score
device_risk_score(device) := score if {
    score := (
        (not device.trusted_device) * 0.3 +
        unusual_location(device) * 0.4 +
        suspicious_user_agent(device.user_agent) * 0.3
    )
}

# Check for unusual location patterns
unusual_location(device) if {
    device.geolocation
    device.geolocation.country != "US"  # Simplified check
}

# Check for suspicious user agents
suspicious_user_agent(user_agent) if {
    contains(lower(user_agent), "bot")
}

suspicious_user_agent(user_agent) if {
    contains(lower(user_agent), "curl")
}

suspicious_user_agent(user_agent) if {
    contains(lower(user_agent), "wget")
}

# Calculate time-based risk
time_risk_score(user) := score if {
    current_hour := time.hour(time.now_ns())
    score := 0.2 if {
        current_hour < 6
    } else := 0.2 if {
        current_hour > 22
    } else := 0.0
}

# Calculate user behavior risk
user_risk_score(user) := score if {
    score := (
        (user.failed_attempts > 3) * 0.5 +
        user.anomaly_score * 0.3 +
        time_risk_score(user) * 0.2
    )
}

# Calculate overall risk score
risk_score := total_risk if {
    device_risk := device_risk_score(input.device_context)
    user_risk := user_risk_score(input.user_context)
    total_risk := min([device_risk + user_risk, 1.0])
}

# Determine risk level
risk_level := "low" if risk_score <= risk_thresholds.low
risk_level := "medium" if {
    risk_score > risk_thresholds.low
    risk_score <= risk_thresholds.medium
}
risk_level := "high" if {
    risk_score > risk_thresholds.medium
    risk_score <= risk_thresholds.high
}
risk_level := "critical" if risk_score > risk_thresholds.high

# Allow access for low-risk standard operations
allow if {
    risk_level == "low"
    not input.request_context.action in high_privilege_actions
    input.request_context.sensitivity_level != "critical"
    reason := "Low risk operation allowed"
}

# Allow medium-risk operations with additional verification
allow if {
    risk_level == "medium"
    not input.request_context.action in high_privilege_actions
    input.request_context.sensitivity_level != "critical"
    input.device_context.trusted_device == true
    reason := "Medium risk operation allowed for trusted device"
}

# Require step-up authentication for high-privilege actions
step_up_required if {
    input.request_context.action in high_privilege_actions
    risk_level in ["medium", "high"]
    reason := "Step-up authentication required for high-privilege action"
}

# Require step-up for critical sensitivity operations
step_up_required if {
    input.request_context.sensitivity_level == "critical"
    risk_level in ["low", "medium", "high"]
    reason := "Step-up authentication required for critical operation"
}

# Deny high-risk operations
allow := false if {
    risk_level == "critical"
    reason := "Access denied due to critical risk level"
}

# Deny access during maintenance windows (example)
allow := false if {
    input.request_context.action == "maintenance"
    maintenance_window
    reason := "Access denied during maintenance window"
}

# Check if currently in maintenance window
maintenance_window if {
    current_hour := time.hour(time.now_ns())
    current_hour >= 2
    current_hour <= 4
}

# Additional security checks for new devices
allow := false if {
    not input.device_context.trusted_device
    risk_score > 0.5
    not has_recent_successful_auth
    reason := "New device requires lower risk score or recent authentication"
}

# Check for recent successful authentication
has_recent_successful_auth if {
    count(input.user_context.previous_logins) > 0
    recent_login := input.user_context.previous_logins[0]
    time_diff := time.now_ns() - time.parse_rfc3339_ns(recent_login.timestamp)
    time_diff < 3600000000000  # 1 hour in nanoseconds
}

# Geographic restrictions (example - can be customized)
allow := false if {
    input.device_context.geolocation.country in ["CN", "KP", "IR"]
    reason := "Access denied from restricted geographic location"
}

# Rate limiting check (simplified)
allow := false if {
    input.user_context.access_count > 100  # per hour
    reason := "Access denied due to rate limiting"
}

# Health check endpoint - always allow
allow if {
    input.request_context.action == "health"
    reason := "Health check always allowed"
}

# Monitoring endpoints - require authentication but lower security
allow if {
    input.request_context.action in ["audit_view", "session_list"]
    risk_level in ["low", "medium"]
    input.user_context.user_id != ""
    reason := "Monitoring access allowed for authenticated user"
} 