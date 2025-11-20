"""
Command Injection Test Case
Expected Issues: 3 high-severity command injection vulnerabilities
CWE-78: OS Command Injection
"""
import os
import subprocess


def ping_host_vulnerable(hostname):
    """VULNERABLE: Command injection via os.system."""
    # Line 13: HIGH - Command injection via os.system
    os.system(f"ping -c 4 {hostname}")


def run_command_vulnerable(user_input):
    """VULNERABLE: Command injection via shell=True."""
    # Line 19: HIGH - Command injection with shell=True
    subprocess.call(f"ls -la {user_input}", shell=True)


def execute_script_vulnerable(script_name):
    """VULNERABLE: Command injection via os.popen."""
    # Line 25: HIGH - Command injection via os.popen
    result = os.popen(f"./scripts/{script_name}.sh").read()
    return result


# Secure versions for comparison
def ping_host_secure(hostname):
    """SECURE: Uses subprocess with list arguments."""
    subprocess.run(["ping", "-c", "4", hostname], check=True)
