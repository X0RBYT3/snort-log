import re
import sys
from collections import defaultdict

# Define a function to parse Snort log file
def parse_snort_log(log_file):
    with open(log_file, 'r') as file:
        log_data = file.read()

    alert_pattern = re.compile(
        r'\[\*\*\] \[(\d+:\d+:\d+)\] (.+?) \[Classification: (.+?)\] \[Priority: (\d+)\] {.*?} (.+?):(.+?) -> (.+?):(.+?) \[\*\*\]'
    )

    alerts = defaultdict(lambda: defaultdict(int))

    for match in alert_pattern.finditer(log_data):
        signature_id, description, classification, priority, src_ip, src_port, dest_ip, dest_port = match.groups()
        alerts[signature_id]['description'] = description
        alerts[signature_id]['classification'] = classification
        alerts[signature_id]['priority'] = priority
        alerts[signature_id]['count'] += 1

    return alerts


# Define a function to print the summary report
def print_alert_summary(alerts):
    print("Snort Alert Summary:")
    print("{:<15} {:<60} {:<20} {:<10} {:<10}".format("Signature ID", "Description", "Classification", "Priority", "Count"))
    print("-" * 105)

    for signature_id, alert_info in alerts.items():
        print("{:<15} {:<60} {:<20} {:<10} {:<10}".format(
            signature_id,
            alert_info['description'][:57] + '...' if len(alert_info['description']) > 57 else alert_info['description'],
            alert_info['classification'],
            alert_info['priority'],
            alert_info['count']
        ))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python snort_log_parser.py <path_to_snort_log>")
        sys.exit(1)

    log_file = sys.argv[1]
    alerts = parse_snort_log(log_file)
    print_alert_summary(alerts)
