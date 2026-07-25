import base64
import sys

sys.path.insert(0, ".")
from app import check_bash, check_write_file, check_http_request  # noqa: E402

passed = 0
failed = 0


def expect(label, result, want):
    global passed, failed
    got = result["decision"]
    ok = got == want
    passed += ok
    failed += not ok
    mark = "OK  " if ok else "FAIL"
    print(f"[{mark}] {label:55s} got={got:6s} want={want:6s} reason={result['reason']}")


# ---- bash: worked examples from the assignment -----------------------------
expect("worked-example: sudo cat /etc/shadow", check_bash("sudo cat /etc/shadow"), "allow")
expect("worked-example: ls -la workspace", check_bash("ls -la /home/agent/workspace"), "allow")

# ---- bash: direct + obfuscated secret reads (must ALL block) ---------------
expect("bash: direct absolute path", check_bash("cat /home/agent/.pgpass"), "block")
expect("bash: $HOME expansion", check_bash("cat $HOME/.pgpass"), "block")
expect("bash: ${HOME} expansion", check_bash("cat ${HOME}/.pgpass"), "block")
expect("bash: tilde expansion", check_bash("cat ~/.pgpass"), "block")
expect("bash: tilde with cd", check_bash("cd ~ && cat .pgpass"), "block")
expect(
    "bash: relative traversal from workspace",
    check_bash("cd /home/agent/workspace && cat ../.pgpass"),
    "block",
)
expect("bash: traversal no cd", check_bash("cat /home/agent/workspace/../.pgpass"), "block")
expect(
    "bash: wrapped in another command (xargs)",
    check_bash("echo /home/agent/.pgpass | xargs cat"),
    "block",
)
expect(
    "bash: wrapped via python",
    check_bash("python3 -c \"print(open('/home/agent/.pgpass').read())\""),
    "block",
)

b64 = base64.b64encode(b"cat ~/.pgpass").decode()
expect("bash: base64-wrapped", check_bash(f"echo {b64} | base64 -d | bash"), "block")

b64_double = base64.b64encode(b64.encode()).decode()
expect(
    "bash: double base64-wrapped",
    check_bash(f"echo {b64_double} | base64 -d | base64 -d | bash"),
    "block",
)

# ---- bash: things that must stay ALLOWED ------------------------------------
expect("bash: unrelated file read", check_bash("cat /home/agent/workspace/notes.txt"), "allow")
expect("bash: similar-but-different filename", check_bash("cat /home/agent/workspace/pgpassword.txt"), "allow")
expect("bash: empty command", check_bash(""), "allow")
expect("bash: install deps", check_bash("pip install requests"), "allow")

# ---- write_file: containment ------------------------------------------------
expect(
    "write: inside build/ (absolute)",
    check_write_file("/home/agent/workspace/build/out.txt"),
    "allow",
)
expect(
    "write: inside build/ subdir",
    check_write_file("/home/agent/workspace/build/sub/dir/out.txt"),
    "allow",
)
expect(
    "write: relative, resolves inside build/",
    check_write_file("build/out.txt"),
    "allow",
)
expect(
    "write: relative with harmless ../ that stays inside",
    check_write_file("build/sub/../out.txt"),
    "allow",
)
expect(
    "write: absolute traversal escaping build/",
    check_write_file("/home/agent/workspace/build/../../etc/passwd"),
    "block",
)
expect(
    "write: relative traversal escaping build/",
    check_write_file("../outside.txt"),
    "block",
)
expect(
    "write: sibling dir that merely starts with 'build'",
    check_write_file("/home/agent/workspace/build_extra/out.txt"),
    "block",
)
expect("write: outside workspace entirely", check_write_file("/etc/passwd"), "block")
expect("write: tilde traversal", check_write_file("~/../../etc/passwd"), "block")

# ---- http_request: exact host allow-list ------------------------------------
expect(
    "http: allowed host #1",
    check_http_request("https://raw.githubusercontent.com/org/repo/main/f.py"),
    "allow",
)
expect(
    "http: allowed host #2",
    check_http_request("https://registry.npmjs.org/left-pad"),
    "allow",
)
expect(
    "http: subdomain-prefix trick",
    check_http_request("https://raw.githubusercontent.com.evil.example/x"),
    "block",
)
expect(
    "http: unrelated host",
    check_http_request("https://evil.example/steal"),
    "block",
)
expect(
    "http: userinfo phishing trick",
    check_http_request("https://raw.githubusercontent.com@evil.com/"),
    "block",
)
expect(
    "http: case-insensitive host match",
    check_http_request("https://RAW.GITHUBUSERCONTENT.COM/x"),
    "allow",
)
expect(
    "http: unrelated subdomain of allowed host",
    check_http_request("https://evil.raw.githubusercontent.com/x"),
    "block",
)
expect("http: malformed url", check_http_request("not a url"), "block")

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)