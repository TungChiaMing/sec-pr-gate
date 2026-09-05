# 故意留漏洞的測試檔，用來驗證 semgrep 有沒有真的抓到東西
import subprocess

AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # hardcoded secret


def run_cmd(user_input):
    return subprocess.check_output(user_input, shell=True)  # command injection


def calc(expr):
    return eval(expr)  # dangerous eval
