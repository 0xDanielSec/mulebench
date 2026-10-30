import mulebench


def test_version_is_exposed() -> None:
    assert mulebench.__version__ == "0.1.0"
