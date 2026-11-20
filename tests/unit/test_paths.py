from __future__ import annotations

import pytest

from termaai.safety.paths import Scope, classify, is_sensitive_home, resolve

WS = "/home/dev/ws"


@pytest.mark.parametrize(
    ("path", "scope"),
    [
        ("notes.txt", Scope.WORKSPACE),
        ("./a/../b", Scope.WORKSPACE),
        ("/home/dev/ws/x", Scope.WORKSPACE),
        ("../x", Scope.OUTSIDE),
        ("/", Scope.ROOT),
        ("/*", Scope.ROOT),
        ("/etc/hosts", Scope.SYSTEM),
        ("/usr/local/bin/x", Scope.SYSTEM),
        ("/tmp/x", Scope.TEMP),
        ("/dev/null", Scope.SAFE_DEVICE),
        ("/dev/sda", Scope.DEVICE),
        ("~", Scope.HOME),
        ("$HOME/.bashrc", Scope.HOME),
        ("/home/other/file", Scope.HOME),
        ("$OUT/file", Scope.UNKNOWN),
        ("/mnt/data", Scope.OUTSIDE),
    ],
)
def test_classify(path: str, scope: Scope) -> None:
    assert classify(path, WS) is scope


def test_sensitive_home_and_resolve() -> None:
    assert is_sensitive_home("~/.ssh/authorized_keys")
    assert is_sensitive_home("${HOME}/.bashrc")
    assert not is_sensitive_home("~/notes.txt")
    assert resolve("a/b.txt", WS) == "/home/dev/ws/a/b.txt"
    assert resolve("/etc/x", WS) == "/etc/x"
