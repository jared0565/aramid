"""load_config's side of API-5 (DEC-4): both layers a person writes are
checked, each problem prints once per process naming the file it is in,
and nothing else about loading changes -- a key is still ignored, or still
used, exactly as before. The suite-wide conftest fixture points the user
layer at a missing file and empties `config._WARNED` for every test."""
import pytest

from aramid import config


@pytest.fixture
def layers(tmp_path, monkeypatch):
    user = tmp_path / "home" / "config.toml"
    user.parent.mkdir()
    monkeypatch.setattr(config, "_user_config_path", lambda: user)
    repo = tmp_path / "repo"
    repo.mkdir()
    return user, repo


def test_each_problem_prints_once_per_process_naming_its_file(layers, capsys):
    user, repo = layers
    user.write_text('colour = "red"\n', encoding="utf-8")
    (repo / "aramid.toml").write_text("[tests]\ncomand = 1\n", encoding="utf-8")

    config.load_config(repo)
    config.load_config(repo)

    assert capsys.readouterr().err == (
        f"aramid: config: {user}: unknown key `colour` -- ignored\n"
        f"aramid: config: {repo / 'aramid.toml'}: unknown key [tests].comand -- ignored\n")


def test_the_same_problem_in_both_layers_prints_for_each(layers, capsys):
    user, repo = layers
    user.write_text('colour = "red"\n', encoding="utf-8")
    (repo / "aramid.toml").write_text('colour = "red"\n', encoding="utf-8")

    config.load_config(repo)

    assert capsys.readouterr().err == (
        f"aramid: config: {user}: unknown key `colour` -- ignored\n"
        f"aramid: config: {repo / 'aramid.toml'}: unknown key `colour` -- ignored\n")


def test_a_clean_config_prints_nothing(layers, capsys):
    user, repo = layers
    user.write_text("[drain]\nmax_items_per_drain = 3\n", encoding="utf-8")
    (repo / "aramid.toml").write_text('[tests]\ncommand = ["pytest"]\n', encoding="utf-8")

    config.load_config(repo)

    assert capsys.readouterr().err == ""


def test_a_warning_changes_nothing_about_what_is_loaded(layers, capsys):
    """WARN only: a wrong-typed value still passes through as written, and
    an unknown key is still dropped -- the warning is the only difference."""
    _, repo = layers
    (repo / "aramid.toml").write_text('colour = "red"\n[tests]\ntimeout_s = "300"\n',
                                      encoding="utf-8")

    cfg = config.load_config(repo)

    assert cfg.tests["timeout_s"] == "300"
    assert not hasattr(cfg, "colour")
    assert "[tests].timeout_s should be a number, got '300'\n" in capsys.readouterr().err


def test_layer_problems_lists_the_user_layer_then_the_repo_layer(layers):
    user, repo = layers
    (repo / "aramid.toml").write_text("b = 1\n", encoding="utf-8")
    user.write_text("a = 1\n", encoding="utf-8")

    assert config.layer_problems(repo) == [
        (user, "unknown key `a` -- ignored"),
        (repo / "aramid.toml", "unknown key `b` -- ignored"),
    ]


def test_layer_problems_is_empty_without_either_layer(layers):
    _, repo = layers
    assert config.layer_problems(repo) == []
