import subprocess
import json
import os
import shutil
from pathlib import Path


class BanditScanner:
    def __init__(self, bandit_path='bandit'):
        self.bandit_path = bandit_path

    def is_available(self):
        """Check if bandit is installed."""
        return shutil.which(self.bandit_path) is not None

    def scan(self, target_path: str) -> dict:
        """
        Run bandit on target_path.

        Returns dict with:
            findings (list): list of finding dicts
            error (str|None): error message if any
            raw_output (str): raw JSON output from bandit
            scanner (str): 'bandit'

        Each finding contains:
            test_id, test_name, severity, confidence,
            filename, line_number, col_offset,
            code, issue_text, more_info, cwe, scanner
        """
        if not self.is_available():
            return {
                'findings': [],
                'error': 'Bandit not installed. Run: pip install bandit',
                'raw_output': '',
                'scanner': 'bandit',
            }

        output = ''
        try:
            result = subprocess.run(
                [self.bandit_path, '-r', target_path, '-f', 'json', '-ll'],
                capture_output=True,
                text=True,
                timeout=120,
            )
            # Bandit returns exit code 1 when findings exist — that's OK
            output = result.stdout or result.stderr
            if not output:
                return {
                    'findings': [],
                    'error': None,
                    'raw_output': '',
                    'scanner': 'bandit',
                }

            data = json.loads(output)
            findings = []
            for result_item in data.get('results', []):
                findings.append({
                    'test_id': result_item.get('test_id', ''),
                    'test_name': result_item.get('test_name', ''),
                    'severity': result_item.get('issue_severity', 'MEDIUM').lower(),
                    'confidence': result_item.get('issue_confidence', 'MEDIUM').lower(),
                    'filename': result_item.get('filename', ''),
                    'line_number': result_item.get('line_number', 0),
                    'code': result_item.get('code', ''),
                    'issue_text': result_item.get('issue_text', ''),
                    'more_info': result_item.get('more_info', ''),
                    'cwe': result_item.get('issue_cwe', {}).get('id', ''),
                    'scanner': 'bandit',
                })
            return {
                'findings': findings,
                'error': None,
                'raw_output': output,
                'scanner': 'bandit',
            }
        except json.JSONDecodeError as e:
            return {
                'findings': [],
                'error': f'Failed to parse bandit output: {e}',
                'raw_output': output,
                'scanner': 'bandit',
            }
        except subprocess.TimeoutExpired:
            return {
                'findings': [],
                'error': 'Bandit scan timed out (>120s)',
                'raw_output': '',
                'scanner': 'bandit',
            }
        except Exception as e:
            return {
                'findings': [],
                'error': str(e),
                'raw_output': '',
                'scanner': 'bandit',
            }

    def get_remediation(self, test_id: str) -> str:
        """Return a remediation hint for the given Bandit test ID."""
        remediations = {
            'B101': 'Remove assert statements from production code or use proper error handling.',
            'B102': 'Avoid using exec(). Use safer alternatives like ast.literal_eval() for data.',
            'B103': 'Set file permissions explicitly and avoid overly permissive modes.',
            'B104': 'Avoid binding to all interfaces (0.0.0.0) in production.',
            'B105': 'Never hardcode passwords. Use environment variables or a secrets manager.',
            'B106': 'Never hardcode passwords in function arguments. Use environment variables.',
            'B107': 'Never hardcode passwords in function arguments. Use environment variables.',
            'B108': 'Use tempfile module for temporary files. Avoid hardcoded temp paths.',
            'B110': 'Handle exceptions explicitly. Avoid bare except: pass blocks.',
            'B112': 'Handle exceptions explicitly. Avoid bare except: continue.',
            'B201': 'Never use Flask debug mode in production. Set DEBUG=False.',
            'B202': 'Never use Flask debug mode with app.run(). Use a production WSGI server.',
            'B301': 'Avoid pickle for untrusted data. Use json.loads() instead.',
            'B302': 'Avoid marshal module. It is not secure.',
            'B303': 'MD5 and SHA1 are weak. Use SHA-256 or stronger.',
            'B304': 'DES cipher is weak. Use AES-256-GCM.',
            'B305': 'ECB mode is insecure. Use CBC or GCM mode.',
            'B306': 'mktemp is insecure. Use tempfile.mkstemp() instead.',
            'B307': 'eval() is dangerous. Never use it on user-supplied input.',
            'B308': 'mark_safe() can cause XSS. Only use on fully sanitized content.',
            'B310': 'urllib.urlopen() with user-controlled URL is a SSRF risk.',
            'B311': 'random module is not cryptographically secure. Use secrets module.',
            'B312': 'Avoid telnet. Use SSH instead.',
            'B313': 'xml.etree.ElementTree is vulnerable to XXE. Use defusedxml.',
            'B314': 'xml.etree.ElementTree is vulnerable to XXE. Use defusedxml.',
            'B315': 'xml module may be vulnerable to XXE. Use defusedxml.',
            'B316': 'xml module may be vulnerable to XXE. Use defusedxml.',
            'B317': 'xml module may be vulnerable to XXE. Use defusedxml.',
            'B318': 'xml.dom.minidom is vulnerable to XXE. Use defusedxml.',
            'B319': 'xml.sax is vulnerable to XXE. Use defusedxml.',
            'B320': 'xml.etree.ElementTree.parse is vulnerable to XXE. Use defusedxml.',
            'B321': 'FTP is insecure. Use SFTP or FTPS.',
            'B322': 'input() in Python 2 is dangerous. Use raw_input() or Python 3.',
            'B323': 'Unverified HTTPS requests. Set verify=True in requests.',
            'B324': 'MD5 and SHA1 are weak. Use SHA-256 or stronger.',
            'B325': 'mktemp is insecure. Use tempfile.mkstemp() instead.',
            'B401': 'Import of insecure telnet module.',
            'B402': 'Import of insecure ftplib module.',
            'B403': 'Import of pickle is potentially insecure.',
            'B404': 'Import of subprocess. Ensure no shell injection vulnerability.',
            'B405': 'Import of xml.etree.ElementTree is potentially insecure. Use defusedxml.',
            'B406': 'Import of xml.etree.cElementTree is potentially insecure.',
            'B407': 'Import of xml.etree is potentially insecure.',
            'B408': 'Import of xml.minidom is potentially insecure.',
            'B409': 'Import of xml.pulldom is potentially insecure.',
            'B410': 'Import of lxml is potentially insecure.',
            'B411': 'Import of xmlrpclib is potentially insecure.',
            'B412': 'Import of httpoxy is insecure.',
            'B413': 'Import of pycrypto is insecure. Use cryptography package.',
            'B501': 'SSL/TLS certificate validation disabled. Enable certificate verification.',
            'B502': 'ssl.wrap_socket called without keyfile. Specify keyfile.',
            'B503': 'ssl.wrap_socket call with ssl_version set to insecure SSLv2 or SSLv3.',
            'B504': 'ssl.wrap_socket call with ssl_version set to insecure SSLv3.',
            'B505': 'Weak cryptographic key. Use at least 2048-bit RSA or 256-bit EC keys.',
            'B506': 'yaml.load() with untrusted data is dangerous. Use yaml.safe_load().',
            'B507': 'Paramiko call without enforcing host key verification.',
            'B601': 'Use of paramiko with pty allows shell injection.',
            'B602': 'subprocess.Popen with shell=True is dangerous. Use list of args instead.',
            'B603': 'subprocess without shell=True, ensure args are sanitized.',
            'B604': 'Function call with shell=True is dangerous.',
            'B605': 'os.system() with user-controlled data is dangerous. Use subprocess.',
            'B606': 'os.popen() is dangerous. Use subprocess instead.',
            'B607': 'Starting a process with partial path. Specify full path.',
            'B608': 'SQL injection risk. Use parameterized queries.',
            'B609': 'Wildcard injection in Linux commands.',
            'B610': 'Django extra() with user data is dangerous.',
            'B611': 'Django RawSQL with user data is dangerous.',
            'B612': 'logging.config.listen() is insecure.',
            'B701': 'jinja2 autoescape is disabled. Enable it to prevent XSS.',
            'B702': 'Use of mako templates without autoescape.',
            'B703': 'Django mark_safe() can cause XSS.',
        }
        return remediations.get(
            test_id,
            'Review the finding and apply the principle of least privilege. '
            'Consult OWASP guidelines for secure coding.',
        )
