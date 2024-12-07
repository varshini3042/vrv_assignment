import re
import pandas as pd
from collections import Counter

# Open and read the log file
with open('server_logs.txt', 'r') as log_file:
    logs_content = log_file.read()

# Define the regex pattern for log parsing
log_pattern = re.compile(
    r'(?P<ip_address>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<http_method>\S+) (?P<url_path>\S+) (?P<protocol>[^"]+)" (?P<status_code>\d+) (?P<response_size>\d+)(?: "(?P<error_message>[^"]+)")?'
)

# Parse the logs into a list of dictionaries
log_entries = []
for log_line in logs_content.strip().split("\n"):
    match = log_pattern.match(log_line)
    if match:
        log_entries.append(match.groupdict())

# Create a DataFrame from the parsed logs
logs_df = pd.DataFrame(log_entries)

# Count requests per IP address
ip_request_counts = Counter(logs_df['ip_address'])
sorted_ip_counts = sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True)

# Print the IP request counts
print(f"{'IP Address':<20}{'Requests':<10}")
for ip, count in sorted_ip_counts:
    print(f"{ip:<20}{count:<10}")

# Save IP request counts to a DataFrame
ip_counts_df = pd.DataFrame(sorted_ip_counts, columns=['IP Address', 'Requests'])

# Find the most accessed URLs
url_access_counts = Counter(logs_df['url_path'])
max_url_access = max(url_access_counts.values())
most_accessed_urls = [(url, max_url_access) for url in url_access_counts if url_access_counts[url] == max_url_access]

# Print the most accessed URLs
print("Most Accessed URLs:")
for url in url_access_counts:
    if url_access_counts[url] == max_url_access:
        print(f"{url}  (Accessed {max_url_access} times)")

# Save most accessed URLs to a DataFrame
url_counts_df = pd.DataFrame(most_accessed_urls, columns=['URL', 'Access Count'])

# Identify suspicious activity (failed logins)
failed_login_attempts = logs_df[(logs_df['status_code'] == '401') | (logs_df['error_message'] == "Invalid credentials")]
failed_login_counts = failed_login_attempts['ip_address'].value_counts()

# Print suspicious activity
print("Suspicious Activity:")
print(f"{'IP Address':<20}{'Failed Attempts':<15}")
for ip, count in failed_login_counts.items():
    print(f"{ip:<20}{count:<15}")

# Save suspicious activity data to a DataFrame
failed_attempts_df = pd.DataFrame(failed_login_counts).reset_index()
failed_attempts_df.columns = ['IP Address', 'Failed Attempts']

# Save all results to CSV files
ip_counts_df.to_csv('ip_request_summary.csv', index=False)
url_counts_df.to_csv('most_accessed_urls.csv', index=False)
failed_attempts_df.to_csv('failed_login_attempts.csv', index=False)

print("Results saved to CSV files:")
print("ip_request_summary.csv")
print("most_accessed_urls.csv")
print("failed_login_attempts.csv")
