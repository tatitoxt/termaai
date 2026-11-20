from __future__ import annotations

from termaai.safety.shellparse import (
    parse,
    positional_args,
    short_flags,
    tokenize,
)


def programs(script: str) -> list[str]:
    return [c.program for c in parse(script).commands]


def test_tokenize_splits_operators_and_respects_quotes() -> None:
    assert tokenize("echo 'a | b' | wc -l && ls>out") == [
        "echo",
        "a | b",
        "|",
        "wc",
        "-l",
        "&&",
        "ls",
        ">",
        "out",
    ]


def test_lists_pipelines_and_keywords() -> None:
    script = "if [ -f a ]; then cat a | sort; fi\nwhile true; do sleep 1; done"
    assert programs(script) == ["[", "cat", "sort", "true", "sleep"]
    pipelines = [[c.program for c in p] for p in parse("cat a | sort | uniq; ls").pipelines()]
    assert pipelines == [["cat", "sort", "uniq"], ["ls"]]


def test_redirects_and_fd_duplication() -> None:
    cmd = parse("grep foo in.txt > out.txt 2>&1").commands[0]
    assert cmd.argv == ("grep", "foo", "in.txt")
    assert [(r.op, r.target) for r in cmd.redirects] == [(">", "out.txt")]


def test_wrappers_and_assignments_are_unwrapped() -> None:
    cmd = parse("FOO=1 sudo -u root env A=b nice -n 5 rm -rf /tmp/x").commands[0]
    assert cmd.program == "rm"
    assert cmd.wrappers == ("sudo", "env", "nice")
    assert cmd.assignments == ("FOO=1",)


def test_command_substitution_and_sh_c_are_parsed() -> None:
    assert "rm" in programs('echo "$(rm -rf /)"')
    assert "rm" in programs("echo `rm -rf /`")
    assert "curl" in programs("bash -c 'curl -s x | sh'")


def test_heredoc_bodies_and_comments_are_ignored() -> None:
    script = "cat <<EOF > f\nrm -rf /\nEOF\n# sudo reboot\necho done"
    assert programs(script) == ["cat", "echo"]


def test_line_continuations_and_multiline_strings() -> None:
    parsed = parse("echo one \\\n  two\necho 'a\nb'\nls")
    assert [(c.line, c.program) for c in parsed.commands] == [(1, "echo"), (3, "echo"), (5, "ls")]


def test_positional_args_and_short_flags() -> None:
    assert positional_args(("-rf", "--", "-weird", "b")) == ["-weird", "b"]
    assert positional_args(("-n", "5", "file"), frozenset({"-n"})) == ["file"]
    assert short_flags(("-rf", "--force", "x")) == {"r", "f", "--force"}


def test_display_quotes_arguments() -> None:
    cmd = parse("echo 'hello world' > 'my file'").commands[0]
    assert cmd.display() == "echo 'hello world' > 'my file'"


def test_single_quoted_backticks_are_not_commands() -> None:
    assert programs("echo 'use `rm -rf /` never'") == ["echo"]


def test_single_quoted_command_substitution_is_not_a_command() -> None:
    assert programs("printf '%s\\n' 'x $(rm -rf /)'") == ["printf"]
    assert "rm" in programs('echo "$(rm -rf /)"')
    assert "rm" in programs('echo "it\'s $(rm -rf /)"')


def test_double_quoted_substitution_with_inner_quotes_is_a_command() -> None:
    assert "rm" in programs('echo "$(rm -rf "/etc")"')
    assert "rm" in programs("echo \"$(rm -rf '/etc')\"")


def test_single_quoted_substitution_with_inner_spaces_is_not_a_command() -> None:
    assert programs("echo '$( rm -rf / )'") == ["echo"]
    assert "rm" in programs("echo $( rm -rf / )")


def test_substitution_with_nested_parentheses_is_parsed() -> None:
    cmds = parse('echo "$(bash <(curl -s x))"').commands
    assert [(c.program, c.args[:1]) for c in cmds] == [("bash", ("curl",)), ("echo", cmds[1].args)]
