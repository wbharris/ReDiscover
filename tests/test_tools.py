import sys
from pathlib import Path

from rediscover.tools import run


def test_run_keeps_stdout_when_the_process_times_out(tmp_path: Path):
    script = tmp_path / "slow.py"
    script.write_text(
        "import time\nprint('www.example.com', flush=True)\ntime.sleep(5)\n",
        encoding="utf-8",
    )
    tool = run("slow", [sys.executable, str(script)], timeout=1)
    assert tool.status == "ran"
    assert tool.output == "www.example.com"
    assert tool.reason == "timed out after 1s"


def test_run_timeout_without_stdout_stays_failed(tmp_path: Path):
    script = tmp_path / "quiet.py"
    script.write_text("import time\ntime.sleep(5)\n", encoding="utf-8")
    tool = run("quiet", [sys.executable, str(script)], timeout=1)
    assert tool.status == "failed"
    assert tool.output == ""
    assert tool.reason == "timed out after 1s"
