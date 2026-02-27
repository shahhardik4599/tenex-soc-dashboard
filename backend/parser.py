import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r'^(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status_code>\d{3}) (?P<response_size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

def parse_nginx_log_lines(log_content: str):
    parsed_logs = []
    
    # Pre-split the lines so we can count them
    lines = log_content.strip().split('\n')
    total_lines = len(lines)
    
    print(f"--- [DEBUG] PARSER STARTED: Loop running for {total_lines} lines ---")
    
    for i, line in enumerate(lines):
        if not line:
            continue
            
        # --- THE PROGRESS TRACKER ---
        # Prints an update every 100 lines on the SAME terminal line 
        if i % 100 == 0 or i == total_lines - 1:
            print(f"Parsing progress: {i}/{total_lines}", end="\r")
            
        match = LOG_PATTERN.match(line)
        if match:
            data = match.groupdict()
            
            try:
                # 1. Safe Date Parsing
                time_str = data['timestamp'].split(' ')[0] 
                parsed_time = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S')
                
                # 2. Safe Size Parsing (Converts "-" to 0)
                size_val = 0 if data['response_size'] == '-' else int(data['response_size'])
                
                # 3. Safe Request Parsing (Handles garbage payloads safely)
                req_parts = data['request'].split()
                method = req_parts[0] if len(req_parts) > 0 else "UNKNOWN"
                
                if len(req_parts) >= 3 and req_parts[-1].startswith("HTTP/"):
                    endpoint = " ".join(req_parts[1:-1])
                elif len(req_parts) == 2:
                    endpoint = req_parts[1]
                else:
                    endpoint = data['request']

                parsed_logs.append({
                    "timestamp": parsed_time,
                    "source_ip": data['source_ip'],
                    "http_method": method,
                    "endpoint": endpoint,
                    "status_code": int(data['status_code']),
                    "response_size": size_val,
                    "user_agent": data.get('user_agent') or "-"
                })
            except Exception as e:
                print(f"\nError parsing date or casting types for line: {line[:50]}... Error: {e}")
                continue
        else:
            print(f"\nRegex failed to match line: {line[:100]}...")
            
    print() # Add a final clean newline when finished
    return parsed_logs