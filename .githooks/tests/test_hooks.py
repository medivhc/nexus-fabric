#!/usr/bin/env python3
"""Hook regression fixtures. Fake Cargo/Harness verdicts are NOT engineering PASS."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1]
ZERO = "0" * 40


class Hooks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nexus hooks fixture ")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.main = self.base / "main"
        self.main.mkdir()
        self.root = self.main
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.pop("CARGO_TARGET_DIR", None)
        self.env.update(NEXUS_AGENT="fixture", FAKE_VERDICT="PASS", FAKE_EXIT="0")
        self.git("init", "-q")
        self.git("config", "user.name", "Hook Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        shutil.copytree(SOURCE, self.main / ".githooks")
        (self.main / "Cargo.toml").write_text("[workspace]\nmembers = []\n")
        (self.main / "note").write_text("base\n")
        self.git("add", ".")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "docs: fixture base")
        self.base_sha = self.git("rev-parse", "HEAD").stdout.strip()
        self.root = self.base / "linked"
        self.git("worktree", "add", "-qb", "linked", str(self.root), cwd=self.main)
        self.bin = self.base / "fake-bin"
        self.bin.mkdir()
        self.events = self.base / "events.jsonl"
        fake = '''#!/usr/bin/env python3
import json, os, pathlib, sys
event = {"tool": pathlib.Path(sys.argv[0]).name, "args": sys.argv[1:],
         "cwd": os.getcwd(), "target": os.getenv("CARGO_TARGET_DIR"),
         "git_local": {k: os.environ[k] for k in os.environ if k in os.getenv("FIXTURE_GIT_VARS", "").split()},
         "caller_preserved": all(os.getenv(k) == "fixture-caller" for k in
           ["NEXUS_LOCALAPI_TOKEN_FILE", "NEXUS_CONFIG_DIR", "NEXUS_HOME", "XDG_RUNTIME_DIR"])}
with open(os.environ["FIXTURE_EVENTS"], "a") as f: f.write(json.dumps(event) + "\\n")
print(json.dumps({"verdict": os.getenv("FAKE_VERDICT")}))
sys.exit(int(os.getenv("FAKE_EXIT", "0")))
'''
        for tool in ["cargo", "nexus-harness"]:
            p = self.bin / tool
            p.write_text(fake)
            p.chmod(0o755)
        self.env.update(PATH=str(self.bin) + os.pathsep + self.env["PATH"],
                        FIXTURE_EVENTS=str(self.events),
                        FIXTURE_GIT_VARS=self.git("rev-parse", "--local-env-vars").stdout)
        for key in ["NEXUS_LOCALAPI_TOKEN_FILE", "NEXUS_CONFIG_DIR", "NEXUS_HOME", "XDG_RUNTIME_DIR"]:
            self.env[key] = "fixture-caller"

    def git(self, *args, cwd=None, check=True, **kwargs):
        return subprocess.run(["git", *args], cwd=cwd or self.root, env=self.env,
                              text=True, capture_output=True, check=check, **kwargs)

    def hook(self, name="pre-push", data="", args=()):
        # Git itself supplies repository-local environment to its hook child.
        stdin = self.base / "hook-stdin"
        stdin.write_text(data)
        return self.git("-c", "core.hooksPath=.githooks", "hook", "run",
                        "--to-stdin=" + str(stdin), name, "--", *args, check=False)

    def event(self):
        self.assertTrue(self.events.exists(), "Cargo/Harness fixture was not invoked")
        return json.loads(self.events.read_text().splitlines()[-1])

    def pushed_code(self):
        p = self.root / "crates" / "fixture" / "src" / "lib.rs"
        p.parent.mkdir(parents=True)
        p.write_text("pub fn fixture() {}\n")
        self.git("add", ".")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "bugfix: fixture code")
        return f"refs/heads/linked {self.git('rev-parse', 'HEAD').stdout.strip()} refs/heads/linked {self.base_sha}\n"

    def summary(self, folder, verdict):
        p = self.root / ".evidence" / folder
        p.mkdir(parents=True, exist_ok=True)
        (p / "summary.json").write_text(json.dumps({"verdict": verdict}))

    def test_linked_current_cargo_and_clean_git_environment(self):
        self.env["CARGO_TARGET_DIR"] = str(self.main / "target")
        result = self.hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        event = self.event()
        self.assertEqual(event["tool"], "cargo")
        self.assertEqual(event["args"], ["run", "--quiet", "--manifest-path", str(self.root / "Cargo.toml"),
                                        "-p", "nexus-harness", "--", "verify", "--fast", "--json"])
        self.assertEqual(event["target"], str(self.root / "target"))
        self.assertEqual(event["cwd"], str(self.root))
        self.assertEqual(event["git_local"], {})
        self.assertTrue(event["caller_preserved"])

    def test_explicit_custom_and_worktree_target_preserved(self):
        for target in [self.base / "external custom target", self.root / "custom target"]:
            with self.subTest(target=target):
                self.env["CARGO_TARGET_DIR"] = str(target)
                self.assertEqual(self.hook().returncode, 0)
                self.assertEqual(self.event()["target"], str(target))

    def test_relative_main_target_redirected(self):
        self.env["CARGO_TARGET_DIR"] = "../main/target"
        self.assertEqual(self.hook().returncode, 0)
        self.assertEqual(self.event()["target"], str(self.root / "target"))

    def test_main_target_preserved(self):
        self.root = self.main
        self.env["CARGO_TARGET_DIR"] = str(self.main / "target")
        self.assertEqual(self.hook().returncode, 0)
        self.assertEqual(self.event()["target"], str(self.main / "target"))

    def test_fast_failure_and_build_exit_rejected(self):
        for verdict, code in [("FAIL", "0"), ("BLOCKED", "0"), ("UNKNOWN", "0"), ("", "0"), ("PASS", "101")]:
            with self.subTest(verdict=verdict, code=code):
                self.env.update(FAKE_VERDICT=verdict, FAKE_EXIT=code)
                self.assertNotEqual(self.hook().returncode, 0)

    def test_stale_is_rejected_but_other_agent_is_scoped_out(self):
        self.summary("verify-other-old", "STALE")
        self.assertEqual(self.hook().returncode, 0)
        self.summary("verify-fixture-old", "STALE")
        self.assertNotEqual(self.hook().returncode, 0)

    def test_agent_identity_falls_back_to_sanitised_user_name_then_placeholder(self):
        # A Rust change activates the STALE scan; an approved review keeps the
        # review gate green so only identity scoping decides the outcome.
        data = self.pushed_code()
        self.summary("review-code-fixture-r1", "APPROVED")
        # NEXUS_AGENT unset: identity derives from the sanitised git user.name
        # ("Hook Fixture" -> "hook-fixture"), so other agents stay out of scope.
        self.env.pop("NEXUS_AGENT")
        self.summary("verify-other-old", "STALE")
        result = self.hook(data=data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.summary("verify-hook-fixture-old", "STALE")
        self.assertNotEqual(self.hook(data=data).returncode, 0)
        # No user.name either: fixed "unknown-agent" placeholder, never empty.
        self.git("config", "user.name", "")
        shutil.rmtree(self.root / ".evidence" / "verify-hook-fixture-old")
        self.summary("verify-unknown-agent-old", "STALE")
        self.assertNotEqual(self.hook(data=data).returncode, 0)

    def test_review_missing_rejected_approved_accepted_requested_rejected(self):
        data = self.pushed_code()
        self.assertNotEqual(self.hook(data=data).returncode, 0)
        self.summary("review-code-fixture-r1", "APPROVED")
        self.assertEqual(self.hook(data=data).returncode, 0)
        self.summary("review-code-fixture-r1", "CHANGES_REQUESTED")
        self.assertNotEqual(self.hook(data=data).returncode, 0)

    def test_commit_message_and_protected_marker(self):
        (self.root / "PRODUCT.md").write_text("fixture contract\n")
        self.git("add", "PRODUCT.md")
        msg = self.base / "message"
        msg.write_text("not a valid subject\n")
        self.assertNotEqual(self.hook("commit-msg", args=(str(msg),)).returncode, 0)
        msg.write_text("bugfix(hooks): fixture contract\n")
        self.assertNotEqual(self.hook("commit-msg", args=(str(msg),)).returncode, 0)
        msg.write_text("bugfix(hooks): fixture contract\n\ncontract: abcdef123456\n")
        self.assertEqual(self.hook("commit-msg", args=(str(msg),)).returncode, 0)

    def test_precommit_keeps_alternate_index_and_cleans_cargo_environment(self):
        self.env["GIT_INDEX_FILE"] = str(self.base / "alternate-index")
        self.git("read-tree", "HEAD")
        p = self.root / "crates" / "fixture.rs"
        p.parent.mkdir()
        p.write_text("pub fn fixture() {}\n")
        self.git("add", str(p))
        result = self.hook("pre-commit")
        self.assertNotEqual(result.returncode, 0, "alternate staged Rust must require review")
        self.assertEqual(self.event()["tool"], "cargo")
        self.assertEqual(self.event()["git_local"], {})
        self.summary("review-code-fixture-r1", "COMMENTED")
        self.assertEqual(self.hook("pre-commit").returncode, 0)
        p.write_text("pub fn fixture() {}  \n")
        self.git("add", str(p))
        self.assertNotEqual(self.hook("pre-commit").returncode, 0)

    def test_install_rejects_shared_core_worktree_without_mutating_config(self):
        self.git("config", "--local", "core.worktree", str(self.main))
        result = subprocess.run(["sh", str(self.root / ".githooks/install.sh")],
                                cwd=self.root, env=self.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("migrate", result.stderr)
        self.assertNotEqual(self.git("config", "--local", "--get", "extensions.worktreeConfig", check=False).returncode, 0)

    def test_install_worktree_scope_does_not_replace_shared_or_main_hook(self):
        self.git("config", "--local", "core.hooksPath", "shared-hooks")
        result = subprocess.run(["sh", str(self.root / ".githooks/install.sh")],
                                cwd=self.root, env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git("config", "--local", "--get", "core.hooksPath").stdout.strip(), "shared-hooks")
        self.assertEqual(self.git("config", "--get", "core.hooksPath", cwd=self.main).stdout.strip(), "shared-hooks")
        self.assertEqual(self.git("config", "--worktree", "--get", "core.hooksPath").stdout.strip(), ".githooks")
        self.assertEqual(self.git("config", "--local", "--get", "extensions.worktreeConfig").stdout.strip(), "true")
        # Normal installed hook dispatch (no -c override).
        self.assertEqual(self.git("hook", "run", "pre-push", "--", input="", check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
