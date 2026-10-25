# WatchTower detection rules.

# MITRE ATT&CK T1110: Brute Force
# Brute Force: 5 login_failed, same Source_IP, Time: 10 min
RULES = [
    {
        "name": "brute_force_login",
        "severity": "high",
        "mitre_technique": "T1110",
        "event_type": "login_failed",
        "group_by": "source_ip",
        "threshold": 5,
        "window_minutes": 10,
    },

# MITRE ATT&CK T1595: Active Scanning
# Web Probe: 5 http_client_error, same Source_IP, Time: 10 min

{
    "name": "web_scanning",
    "severity": "medium",
    "mitre_technique": "T1595",
    "event_type": "http_client_error",
    "group_by": "source_ip",
    "threshold": 5,
    "window_minutes": 10,
},


# MITRE ATT&CK T1110.003: Password Spraying
# Password Spraying: 4 different usernames, same Source_IP, Time: 10 min

{
    "name": "password_spraying",
    "severity": "high",
    "mitre_technique": "T1110.003",
    "event_type": "login_failed",
    "group_by": "source_ip",
    "count_distinct": "username",
    "threshold": 4,
    "window_minutes": 10,
},
]