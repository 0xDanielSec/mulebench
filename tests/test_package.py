import honeyledger


def test_version_is_exposed() -> None:
    assert honeyledger.__version__ == "0.1.0"
