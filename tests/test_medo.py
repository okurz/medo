"""
tests for medo.

isort:skip_file
"""

import os.path
import sys

import pytest

from medo import medo  # SUT


def test_help(capsys):
    sys.argv[1:] = ["--help"]
    with pytest.raises(SystemExit):
        medo.main()
    captured = capsys.readouterr()
    for sensitive_opt in ["--github-token", "--gitlab-token", "--bugzilla-password", "--redmine-token", "--imap-password"]:
        assert sensitive_opt in captured.out
    click_cmd = medo.get_command(medo.app)
    for param in click_cmd.params:
        if any(secret in (param.name or "") for secret in ["token", "password"]):
            assert getattr(param, "show_default", None) is False


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
        (
            "https://bz.example.com",
            {
                "id": "https://bz.example.com/",
                "result": {
                    "bugs": [
                        {"id": 1, "product": "P1", "priority": "P1", "severity": "S1", "status": "VERIFIED", "summary": "Bug 1"},
                        {"id": 2, "product": "P2", "priority": "P2", "severity": "S2", "status": "RESOLVED", "summary": "Bug 2"},
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
        "exclude verified bugs while keeping resolved bugs in bugzilla notifications",
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
    mock_get = None
    if host:
        mock_get = mocker.patch("medo.medo.get_json", return_value=response)
    res = medo.bugzilla_notifications(args)
    if expected_len == 0:
        assert res == []
    else:
        assert len(res) == expected_len
        assert "VERIFIED" not in "\n".join(res)
        assert mock_get is not None
        params_str = mock_get.call_args[1]["params"]["params"]
        assert '"assigned_to": "user@example.com"' in params_str


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


@pytest.mark.parametrize(
    "host,expected_len",
    [
        (None, 0),
        ("https://progress.example.com", 2),
    ],
    ids=[
        "empty notifications when redmine host is unconfigured",
        "format redmine issues with valid url and limit by max_lines",
    ],
)
def test_redmine_notifications(mocker, host, expected_len):
    args = medo.ArgsNamespace(
        redmine_host=host,
        redmine_token="secret",
        max_lines=1,
    )
    if host:
        mocker.patch(
            "medo.medo.get_json",
            return_value={
                "total_count": 2,
                "issues": [
                    {"id": 100, "project": {"name": "Proj1"}, "priority": {"name": "High"}, "subject": "Fix bug"},
                    {"id": 101, "project": {"name": "Proj2"}, "priority": {"name": "Low"}, "subject": "Refactor"},
                ],
            },
        )
    res = medo.redmine_notifications(args)
    if expected_len == 0:
        assert res == []
    else:
        assert len(res) == expected_len
        assert "https://progress.example.com/issues/100 +Proj1 (High) Fix bug" in res[1]


def test_github_notifications_unconfigured():
    args = medo.ArgsNamespace(github_token=None)
    assert medo.github_notifications(args) == []


def test_parse_args_masks_sensitive_tokens(mocker):
    sys.argv[1:] = ["ls", "--verbose", "4", "--github-token", "mysecrettoken"]
    mock_log = mocker.patch("medo.medo.log.debug")
    medo.parse_args()
    logged_msg = str(mock_log.call_args[0][0])
    assert "mysecrettoken" not in logged_msg
    assert "***" in logged_msg


def test_gitlab_notifications_unconfigured():
    args = medo.ArgsNamespace(gitlab_host=None)
    assert medo.gitlab_notifications(args) == []


def test_gitlab_notifications_v4_success(mocker):
    args = medo.ArgsNamespace(
        gitlab_host="https://gitlab.example.com",
        gitlab_token="token123",
        gitlab_merge_requests1="group/proj",
        max_lines=5,
    )

    def mock_requests_get(url, **kwargs):
        resp = mocker.MagicMock()
        resp.ok = True
        resp.status_code = 200
        if "api/v4/todos" in url:
            resp.json.return_value = [
                {
                    "target_url": "https://gitlab.example.com/group/proj/-/issues/1",
                    "action_name": "assigned",
                    "target": {"title": "Issue title"},
                }
            ]
        elif "merge_requests" in url:
            resp.json.return_value = [
                {
                    "web_url": "https://gitlab.example.com/group/proj/-/merge_requests/2",
                    "title": "MR title",
                    "author": {"name": "Author Name"},
                }
            ]
        return resp

    mocker.patch("requests.get", side_effect=mock_requests_get)
    res = medo.gitlab_notifications(args)
    assert any("https://gitlab.example.com/group/proj/-/issues/1 assigned Issue title" in line for line in res)
    assert any("https://gitlab.example.com/group/proj/-/merge_requests/2 MR title @Author Name" in line for line in res)


def test_gitlab_notifications_v4_fallback_to_v3(mocker):
    args = medo.ArgsNamespace(
        gitlab_host="https://gitlab.example.com",
        gitlab_token="token123",
        gitlab_merge_requests1=None,
        max_lines=5,
    )

    def mock_requests_get(url, **kwargs):
        resp = mocker.MagicMock()
        if "api/v4/" in url:
            resp.ok = False
            resp.status_code = 404
            resp.reason = "Not Found"
        else:
            resp.ok = True
            resp.status_code = 200
            resp.json.return_value = [
                {
                    "target_url": "https://gitlab.example.com/group/proj/-/issues/10",
                    "action_name": "mentioned",
                    "target": {"title": "Legacy Issue"},
                }
            ]
        return resp

    mocker.patch("requests.get", side_effect=mock_requests_get)
    res = medo.gitlab_notifications(args)
    assert any("Legacy Issue" in line for line in res)
