from seed_steps import terminal_style as ts


def test_should_use_color_respects_no_color_flag(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(ts.sys.stdout, "isatty", lambda: True)

    assert ts.should_use_color(no_color_flag=True) is False


def test_should_use_color_respects_no_color_env(monkeypatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(ts.sys.stdout, "isatty", lambda: True)

    assert ts.should_use_color() is False


def test_should_use_color_respects_dumb_term(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.setattr(ts.sys.stdout, "isatty", lambda: True)

    assert ts.should_use_color() is False


def test_should_use_color_respects_non_tty_stdout(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(ts.sys.stdout, "isatty", lambda: False)

    assert ts.should_use_color() is False
