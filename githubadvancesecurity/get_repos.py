import requests
import os
import json
from typing import List, Dict
from dotenv import load_dotenv
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

class SecretManager:
    def __init__(self):
        load_dotenv()
        vault_url = os.getenv('AZURE_KEYVAULT_URL')
        if not vault_url:
            raise ValueError("Azure Key Vault URL not found. Set AZURE_KEYVAULT_URL in environment variables.")
        
        credential = DefaultAzureCredential()
        self.secret_client = SecretClient(vault_url=vault_url, credential=credential)
    
    def get_secret(self, secret_name: str) -> str:
        try:
            return self.secret_client.get_secret(secret_name).value
        except Exception as e:
            raise ValueError(f"Failed to retrieve secret {secret_name}: {str(e)}")

class GitHubRepoFetcher:
    def __init__(self):
        # Initialize secret manager
        self.secret_manager = SecretManager()
        self.token = self.secret_manager.get_secret('github-token')
        if not self.token:
            raise ValueError("GitHub token not found in Key Vault")
        
    def get_repositories(self, organization: str = None, user: str = None) -> List[Dict]:
        headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        if organization:
            url = f'https://api.github.com/orgs/{organization}/repos'
        elif user:
            url = f'https://api.github.com/users/{user}/repos'
        else:
            url = 'https://api.github.com/user/repos'
            
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        return response.json()
    
    def get_branches(self, repo_full_name: str) -> List[Dict]:
        """
        Get list of branches for a specific repository
        :param repo_full_name: Full name of repository (e.g. 'owner/repo')
        :return: List of branches
        """
        headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        url = f'https://api.github.com/repos/{repo_full_name}/branches'
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        return response.json()

    def get_org_repositories(self, org_name: str) -> List[Dict]:
        """
        Get all repositories for a specific organization
        :param org_name: Name of the organization
        :return: List of repositories
        """
        headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        url = f'https://api.github.com/orgs/{org_name}/repos'
        repositories = []
        page = 1
        
        while True:
            response = requests.get(f"{url}?page={page}&per_page=100", headers=headers)
            response.raise_for_status()
            repos = response.json()
            if not repos:
                break
            repositories.extend(repos)
            page += 1
            
        return repositories

    def check_code_scanning_status(self, repo_full_name: str) -> Dict:
        """
        Check if code scanning is enabled and get alerts for a repository
        :param repo_full_name: Full name of repository (e.g. 'owner/repo')
        :return: Dictionary with code scanning status and alerts count
        """
        headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        try:
            # Check code scanning alerts (this endpoint will fail if code scanning is not enabled)
            alerts_url = f'https://api.github.com/repos/{repo_full_name}/code-scanning/alerts'
            alerts_response = requests.get(alerts_url, headers=headers)
            
            if alerts_response.status_code == 404:
                return {
                    'enabled': False,
                    'alerts_count': 0,
                    'message': 'Code scanning is not enabled'
                }
            
            alerts_response.raise_for_status()
            alerts = alerts_response.json()
            
            return {
                'enabled': True,
                'alerts_count': len(alerts),
                'message': f'Code scanning is enabled with {len(alerts)} alerts'
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'enabled': False,
                'alerts_count': 0,
                'message': f'Error checking code scanning status: {str(e)}'
            }

    def check_secret_scanning_status(self, repo_full_name: str) -> Dict:
        """
        Check if secret scanning is enabled and get alerts for a repository
        :param repo_full_name: Full name of repository (e.g. 'owner/repo')
        :return: Dictionary with secret scanning status and alerts count
        """
        headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        try:
            # Check secret scanning alerts
            alerts_url = f'https://api.github.com/repos/{repo_full_name}/secret-scanning/alerts'
            alerts_response = requests.get(alerts_url, headers=headers)
            
            if alerts_response.status_code == 404:
                return {
                    'enabled': False,
                    'alerts_count': 0,
                    'message': 'Secret scanning is not enabled'
                }
            
            alerts_response.raise_for_status()
            alerts = alerts_response.json()
            
            return {
                'enabled': True,
                'alerts_count': len(alerts),
                'message': f'Secret scanning is enabled with {len(alerts)} alerts'
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'enabled': False,
                'alerts_count': 0,
                'message': f'Error checking secret scanning status: {str(e)}'
            }

    def generate_html_report(self, repos: List[Dict]) -> str:
        """
        Generate enhanced HTML report of repositories and their branches
        """
        total_repos = len(repos)
        html = """
        <html>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <style>
                body {
                    font-family: 'Segoe UI', Arial, sans-serif;
                    background: #f4f6fb;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    max-width: 1100px;
                    margin: 30px auto;
                    background: #fff;
                    border-radius: 12px;
                    box-shadow: 0 4px 24px rgba(44,62,80,0.08);
                    padding: 32px 32px 24px 32px;
                }
                .header {
                    background: linear-gradient(90deg, #007bff 0%, #00c6ff 100%);
                    color: #fff;
                    padding: 24px 32px 16px 32px;
                    border-radius: 12px 12px 0 0;
                    margin: -32px -32px 24px -32px;
                }
                h2 {
                    margin: 0 0 8px 0;
                    font-size: 2.1rem;
                    font-weight: 700;
                }
                .timestamp {
                    color: #e0e0e0;
                    font-size: 1rem;
                    margin-bottom: 0;
                }
                .summary {
                    background: #e9f7ef;
                    color: #1e4620;
                    border-left: 5px solid #28a745;
                    padding: 14px 18px;
                    border-radius: 6px;
                    margin-bottom: 24px;
                    font-size: 1.08rem;
                }
                table {
                    border-collapse: collapse;
                    width: 100%;
                    background: #fff;
                }
                th, td {
                    border: 1px solid #e3e6ed;
                    padding: 13px 10px;
                    text-align: left;
                }
                th {
                    background: #f7fafd;
                    color: #2c3e50;
                    font-weight: 600;
                    font-size: 1.05rem;
                }
                tr:hover {
                    background: #f1f7ff;
                }
                tr:nth-child(even) {
                    background: #f9fbfd;
                }
                a {
                    color: #007bff;
                    text-decoration: none;
                    font-weight: 500;
                }
                a:hover {
                    text-decoration: underline;
                }
                .badge {
                    display: inline-block;
                    padding: 3px 10px;
                    border-radius: 12px;
                    font-size: 0.98em;
                    font-weight: 600;
                    color: #fff;
                }
                .badge-green {
                    background: #28a745;
                }
                .badge-red {
                    background: #dc3545;
                }
                .badge-gray {
                    background: #6c757d;
                }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h2>GitHub Repositories Security Report</h2>
                    <div class='timestamp'>Generated on: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</div>
                </div>
                <div class='summary'>
                    <b>Total repositories scanned:</b> """ + str(total_repos) + """<br>
                    <span style='font-size:0.98em;'>This report summarizes the security scanning status (code & secret scanning) for all repositories.</span>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Repository</th>
                            <th>URL</th>
                            <th>Branches</th>
                            <th>Code Scanning Status</th>
                            <th>Secret Scanning Status</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for repo in repos:
            try:
                branches = self.get_branches(repo['full_name'])
                branch_list = ", ".join([b['name'] for b in branches])
                code_scan_status = self.check_code_scanning_status(repo['full_name'])
                code_status_class = "badge-green" if code_scan_status['enabled'] else "badge-red"
                code_status_text = f"{code_scan_status['message']} ({code_scan_status['alerts_count']} alerts)" if code_scan_status['enabled'] else code_scan_status['message']
                secret_scan_status = self.check_secret_scanning_status(repo['full_name'])
                secret_status_class = "badge-green" if secret_scan_status['enabled'] else "badge-red"
                secret_status_text = f"{secret_scan_status['message']} ({secret_scan_status['alerts_count']} alerts)" if secret_scan_status['enabled'] else secret_scan_status['message']
            except Exception as e:
                branch_list = "Error fetching branches"
                code_status_text = secret_status_text = "Error checking status"
                code_status_class = secret_status_class = "badge-gray"
            html += f"""
                <tr>
                    <td>{repo['name']}</td>
                    <td><a href='{repo['html_url']}'>{repo['html_url']}</a></td>
                    <td>{branch_list}</td>
                    <td><span class='badge {code_status_class}'>{code_status_text}</span></td>
                    <td><span class='badge {secret_status_class}'>{secret_status_text}</span></td>
                </tr>
            """
        html += """
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        return html

    def send_email_report(self, html_content: str, recipient_email: str):
        """
        Send HTML report via email using credentials from Key Vault
        """
        try:
            sender_email = self.secret_manager.get_secret('email-user')
            sender_password = self.secret_manager.get_secret('email-password')
            
            msg = MIMEMultipart()
            msg['Subject'] = 'GitHub Repositories and Branches Report'
            msg['From'] = sender_email
            msg['To'] = recipient_email
            
            msg.attach(MIMEText(html_content, 'html'))
            
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)
            print(f"Report sent successfully to {recipient_email}")
        except Exception as e:
            print(f"Failed to send email: {str(e)}")

def main():
    try:
        load_dotenv()
        fetcher = GitHubRepoFetcher()
        
        # Load organizations from JSON file
        org_file_path = Path(__file__).parent / 'organizations.json'
        if not org_file_path.exists():
            raise FileNotFoundError("organizations.json file not found")
            
        with open(org_file_path, 'r') as f:
            org_data = json.load(f)
            
        all_repos = []
        for org in org_data.get('organizations', []):
            if not org.get('enabled', True):
                continue
                
            org_name = org['name']
            print(f"\nFetching repositories for organization: {org_name}")
            org_repos = fetcher.get_org_repositories(org_name)
            print(f"Found {len(org_repos)} repositories")
            
            # Check code scanning status for repositories
            print(f"\nChecking code scanning status for {org_name} repositories:")
            for repo in org_repos:
                status = fetcher.check_code_scanning_status(repo['full_name'])
                print(f"{repo['full_name']}: {status['message']}")
                
            all_repos.extend(org_repos)
        
        # Generate and send report for all repositories
        if all_repos:
            html_report = fetcher.generate_html_report(all_repos)
            fetcher.send_email_report(html_report, "schaskar.ml@gmail.com")
            print("\nReport generated and sent successfully")
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()