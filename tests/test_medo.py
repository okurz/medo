"""
tests for medo.

isort:skip_file
"""

import os.path
import sys

import pytest

from medo import medo  # SUT


def test_help():
    sys.argv[1:] = ["--help"]
    with pytest.raises(SystemExit):
        medo.main()


def test_default(mocker):
    sys.argv[1:] = ["-c", os.path.join(os.path.dirname(__file__), "medorc"), "ls"]
    args = medo.parse_args()
    mocker.patch("requests.get")
    mocker.patch("subprocess.check_output")
    mocker.patch("subprocess.call")
    args.timeout = 1
    args.imap_host = None
    m = medo.MeDo(args)
    m.ls()


def test_get_json_error_handling(mocker):
    mock_resp = mocker.MagicMock()
    mock_resp.ok = False
    mock_resp.reason = "Unauthorized"
    mocker.patch("requests.get", return_value=mock_resp)
    with pytest.raises(RuntimeError, match="github access failed: Unauthorized"):
        medo.get_json("github", "https://api.github.com")


def test_ls_handles_service_exception_gracefully(mocker, capsys):
    args = medo.ArgsNamespace(timeout=1.0)
    m = medo.MeDo(args)
    m.dispatch = {
        "failing": lambda _: (_ for _ in ()).throw(RuntimeError("Service down")),
        "succeeding": lambda _: ["## service header", "item 1"],
    }
    m.ls()
    captured = capsys.readouterr()
    assert "## service header\nitem 1" in captured.out


@pytest.mark.parametrize(
    "host,response,expected_len",
    [
        (None, None, 0),
        ("https://bz.example.com", {"error": {"message": "Invalid password"}}, 0),
        ("https://bz.example.com", {"result": None}, 0),
        (
            "https://bz.example.com",
            {
                "id": "https://bz.example.com/",
                "result": {
                    "bugs": [
                        {"id": 1, "product": "P1", "priority": "P1", "severity": "S1", "status": "NEW", "summary": "Bug 1"},
                        {"id": 2, "product": "P2", "priority": "P2", "severity": "S2", "status": "CONFIRMED", "summary": "Bug 2"},
                    ]
                },
            },
            2,
        ),
    ],
    ids=[
        "empty notifications when bugzilla host is unconfigured",
        "gracefully handle bugzilla error response",
        "gracefully handle bugzilla response with null result",
        "format bugzilla notifications and limit by max_lines",
    ],
)
def test_bugzilla_notifications(mocker, host, response, expected_len):
    args = medo.ArgsNamespace(
        bugzilla_host=host,
        bugzilla_user="user",
        bugzilla_password=None,
        bugzilla_account="user@example.com",
        max_lines=1,
    )
    if host:
        mocker.patch("medo.medo.get_json", return_value=response)
    res = medo.bugzilla_notifications(args)
    if expected_len == 0:
        assert res == []
    else:
        assert len(res) == expected_len
        assert "https://bz.example.com/1 P1 P1 S1 NEW Bug 1" in res[1]


@pytest.mark.parametrize(
    "osc_found,expected_headers",
    [
        (False, []),
        (True, ["\n## OBS TODOs", "\n### OBS requests"]),
    ],
    ids=[
        "empty list when osc executable is not found",
        "both todos and requests sections included when osc is available",
    ],
)
def test_obs_sections(mocker, osc_found, expected_headers):
    args = medo.ArgsNamespace(max_lines=5)
    mocker.patch("shutil.which", return_value="/usr/bin/osc" if osc_found else None)
    if osc_found:
        mocker.patch(
            "subprocess.check_output",
            side_effect=[b"todo line 1\n", b"request line 1\n"],
        )
    res = medo.obs(args)
    for header in expected_headers:
        assert header in res
    if not osc_found:
        assert res == []
