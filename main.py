import os
import requests
import json

# Setup
ORG_NAME = os.getenv('INPUT_ORG_NAME')
REPO_NAME = os.getenv('INPUT_REPO_NAME')
GITHUB_TOKEN = os.getenv('INPUT_GITHUB_TOKEN')

headers = {
    'Authorization': f'Bearer {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.vixen-preview+json',
    'Content-Type': 'application/json'
}

def fetch_code_scanning_alerts(owner, name):
    query = """
    query($owner: String!, $name: String!) {
        repository(owner: $owner, name: $name) {
            codeScanningAlerts(first: 100) {
                nodes {
                    createdAt
                    closed
                    rule {
                        name
                    }
                    securityVulnerability {
                        package {
                            name
                        }
                        advisory {
                            summary
                            severity
                        }
                    }
                }
            }
        }
    }
    """
    variables = {
        "owner": owner,
        "name": name
    }
    response = execute_graphql_query(query, variables)
    alerts = response['data']['repository']['codeScanningAlerts']['nodes']
    return alerts

def execute_graphql_query(query, variables):
    request = requests.post('https://api.github.com/graphql', headers=headers, json={'query': query, 'variables': variables})
    if request.status_code == 200:
        return request.json()
    else:
        raise Exception(f"Query failed to run by returning code of {request.status_code}. {request.text}")

def generate_markdown_summary(org_name, repo_name, alerts):
    markdown_lines = [
        "## Code Scanning Alerts Report",
        "| S.No | Org/Repo Name | Package Name | Severity | Summary | ",
        "| ---- | ------------- | ------------ | -------- | ------- | "
    ]
    for index, alert in enumerate(alerts, start=1):
        package_name = alert['securityVulnerability']['package']['name']
        severity = alert['securityVulnerability']['advisory']['severity']
        summary = alert['securityVulnerability']['advisory']['summary']

        markdown_lines.append(
            f"| {index} | {org_name}/{repo_name} | {package_name} | {severity} | {summary} |"
        )
    return "\n".join(markdown_lines)

def write_markdown_to_file(content, filename):
    with open(filename, 'w') as file:
        file.write(content)

def main():
    alerts = fetch_code_scanning_alerts(ORG_NAME, REPO_NAME)
    if not alerts:
        print("No code scanning alerts to report.")
        return
        
    markdown_summary = generate_markdown_summary(ORG_NAME, REPO_NAME, alerts)
    print(markdown_summary)
    write_markdown_to_file(markdown_summary, "codescanning_vulnerability_report.md")

if __name__ == '__main__':
    main()
