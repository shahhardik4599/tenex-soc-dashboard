import re
from datetime import datetime

# UPDATED REGEX: The (?: "(?P<referer>... )? at the end makes the Combined fields optional!
# This means it will successfully read BOTH Nginx Common and Nginx Combined formats.
LOG_PATTERN = re.compile(
    r'^(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<http_method>[A-Z]+) (?P<endpoint>\S+) [^"]+" '
    r'(?P<status_code>\d{3}) (?P<response_size>\d+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

def parse_nginx_log_lines(log_content: str):
    parsed_logs = []
    
    for line in log_content.strip().split('\n'):
        if not line:
            continue
            
        match = LOG_PATTERN.match(line)
        if match:
            data = match.groupdict()
            
            try:
                # Convert timestamp string to Python datetime object
                # Example: 26/Feb/2026:13:55:36 +0000
                time_str = data['timestamp'].split(' ')[0] 
                parsed_time = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S')
                
                parsed_logs.append({
                    "timestamp": parsed_time,
                    "source_ip": data['source_ip'],
                    "http_method": data['http_method'],
                    "endpoint": data['endpoint'],
                    "status_code": int(data['status_code']),
                    "response_size": int(data['response_size']),
                    # If it's the Common format, these will be None, so we default to "-"
                    "user_agent": data.get('user_agent') or "-"
                })
            except Exception as e:
                print(f"Error parsing date or casting types for line: {line}. Error: {e}")
                continue
        else:
            print(f"Regex failed to match line: {line}")
            
    return parsed_logs