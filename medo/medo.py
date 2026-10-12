#!/usr/bin/env python3

import concurrent.futures
import configparser
import email
import email.header
import imaplib
import json
import logging
import os
import shutil
import subprocess
import sys
import urllib.parse
from typing import Any, Callable, Dict, List, Optional

import certifi
import click
import requests
import typer
from typer.main import get_command

DEFAULTS = {
    "MAX_LINES": 20,
    "CONFIG_PATH": os.path.expanduser("~") + "/.medorc",
    "CONFIG_USAGE": """
You are missing configuration file with the proper format.
Example:
[github]
github-username = me
github-token = <my_token>

[gitlab]
gitlab-host = https://gitlab.example.com
gitlab-token = <my_gitlab_token>
gitlab-merge-requests1 = <user>/<project>

[bugzilla]
bugzilla-host = https://apibugzilla.example.com
bugzilla-user = me
bugzilla-password = my_password
bugzilla-account = me@example.com
""",
}

logging.basicConfig()
log = logging.getLogger(sys.argv[0] if __name__ == "__main__" else __name__)


def get_json(name: str, *args: Any, **kwargs: Any) -> Any:
    """Retrieve JSON from a (REST) API server after checking correct response."""
    r = requests.get(*args, **kwargs)
    if not r.ok:
        raise RuntimeError("%s access failed: %s" % (name, r.reason))
    return r.json()


def get_todo_txt(args: Any) -> List[str]:
    if not shutil.which("t"):
        return []
    t_ls_out = subprocess.check_output(["t", "ls"]).splitlines()
    return ["\n## t (%s tasks)" % len(t_ls_out)] + [line.decode("utf-8") for line in t_ls_out][: args.max_lines]


def github_notifications(args: Any) -> List[str]:
    if not args.github_token:
        log.debug("no github_token configured, ignoring")
        return []
    github_auth = (args.github_username, args.github_token)
    r = get_json("github", "https://api.github.com/notifications", auth=github_auth, headers={"Accept": "application/vnd.github.v3+json"})
    gh = r[: args.max_lines]
    gh_out = sorted(
        [
            "%s %s"
            % (
                i["subject"]["url"].replace("https://api.github.com/repos", "https://github.com"),
                i["subject"]["title"],
            )
            for i in gh
        ]
    )
    return ["\n## github"] + gh_out


def gitlab_notifications(args: Any) -> List[str]:
    def get(route: str, base: str = "api/v3/") -> Any:
        return get_json("gitlab", urllib.parse.urljoin(args.gitlab_host, base + route), headers={"PRIVATE-TOKEN": args.gitlab_token}, verify=certifi.where())

    if not args.gitlab_host:
        log.debug("no gitlab_host configured, ignoring")
        return []

    todos = get("todos")
    gl = ["\n## gitlab %s" % args.gitlab_host] + todos
    # TODO do not have any todos right now

    if args.gitlab_merge_requests1:
        merge_requests_json = get("projects/%s/merge_requests" % urllib.parse.quote_plus(args.gitlab_merge_requests1) + "?state=opened")
        merge_requests = ["%s %s @%s" % (i["web_url"], i["title"], i["author"]["name"]) for i in merge_requests_json]
        gl += ["\n### gitlab merge requests %s" % args.gitlab_merge_requests1] + merge_requests
    return gl


def redmine_notifications(args: Any) -> List[str]:
    if not args.redmine_host:
        log.debug("no redmine_host configured, ignoring")
        return []

    base_url = args.redmine_host.rstrip("/") + "/"
    url = urllib.parse.urljoin(base_url, f"issues.json?limit={args.max_lines}&assigned_to_id=me")
    auth = (args.redmine_token, "") if args.redmine_token else None
    r = get_json("progress", url, auth=auth)

    def ticket_str(i: Any) -> str:
        return "%s +%s (%s) %s" % (f"{base_url}issues/{i['id']}", i["project"]["name"], i["priority"]["name"], i["subject"])

    redmine_issues = [ticket_str(i) for i in r["issues"]][: args.max_lines]
    rm = ["\n## %s (%s issues)" % (args.redmine_host, r.get("total_count", len(redmine_issues)))] + redmine_issues
    return rm


def bugzilla_notifications(args: Any) -> List[str]:
    """Get notifications from bugzilla instance.

    Reference: https://www.bugzilla.org/docs/4.4/en/html/api/Bugzilla/WebService/Bug.html#search
    """
    if not args.bugzilla_host:
        log.debug("no bugzilla_host configured, ignoring")
        return []

    def get(method: str, params: Any) -> Any:
        r_params = {"method": method, "params": json.dumps([params])}
        auth = (args.bugzilla_user, args.bugzilla_password) if (args.bugzilla_user and args.bugzilla_password) else None
        return get_json("bugzilla", urllib.parse.urljoin(args.bugzilla_host, "jsonrpc.cgi"), auth=auth, params=r_params)

    def bug_str(bz_id: str, b: Any) -> str:
        return " ".join([bz_id + str(b["id"]), b["product"], b["priority"], b["severity"], b["status"], b["summary"]])

    assigned = get("Bug.search", {"assigned_to": args.bugzilla_account, "resolution": ""})
    if not isinstance(assigned, dict) or assigned.get("error") or not assigned.get("result"):
        if isinstance(assigned, dict) and assigned.get("error"):
            log.warning("bugzilla error: %s", assigned["error"].get("message", assigned["error"]))
        return []
    bz_id = assigned["id"] if isinstance(assigned.get("id"), str) else args.bugzilla_host.rstrip("/") + "/"
    assigned_str = [bug_str(bz_id, i) for i in assigned["result"]["bugs"]][: args.max_lines]
    # another idea was to look for user as requestee but it looks like this is not accessible over current API
    bz = ["\n## bugzilla %s" % args.bugzilla_host] + assigned_str
    return bz


def obs(args: Any) -> List[str]:
    """OBS TODOs, pending reviews, submit requests."""
    if not shutil.which("osc"):
        log.debug("no osc found, ignoring")
        return []
    log.debug("querying OBS TODOs")
    osc_my = subprocess.check_output(["osc", "my"])
    osc_out = [line.decode("utf-8") for line in osc_my.splitlines()][: args.max_lines]
    osc = ["\n## OBS TODOs"] + osc_out
    osc_my_rq = subprocess.check_output(["osc", "my", "rq"])
    osc_out_rq = [line.decode("utf-8") for line in osc_my_rq.splitlines()][: args.max_lines]
    osc += ["\n### OBS requests"] + osc_out_rq
    return osc


def email_todos(args: Any) -> List[str]:
    if not args.imap_host:
        log.debug("no imap_host configured, ignoring")
        return []
    imap = imaplib.IMAP4_SSL(args.imap_host)
    imap.login(args.imap_username, args.imap_password)
    imap.select("INBOX/todo")
    status, messages = imap.search(None, "ALL")
    assert status == "OK"
    msgs = [imap.fetch(i, "(BODY.PEEK[HEADER])") for i in messages[0].split()]

    emails = []
    for _, data in msgs:
        if data and len(data) > 0 and isinstance(data[0], tuple):
            header_bytes = data[0][1]
            if isinstance(header_bytes, bytes):
                emails.append(email.message_from_bytes(header_bytes))

    mail_out = [" ".join([str(e["From"]), str(e["Date"]), str(e["Subject"])]) for e in emails]
    email_str = ["\n## email TODOs (%s)" % len(mail_out)] + mail_out[: args.max_lines]
    return email_str


class MeDo:
    """Main object constructing and calling retrieval objects."""

    def __init__(self, args: Any) -> None:
        """Construct object and save forwarded arguments."""
        self.args = args
        self.dispatch: Dict[str, Callable[[Any], List[str]]] = {
            "todo_txt": get_todo_txt,
            "redmine": redmine_notifications,
            "email": email_todos,
            "github": github_notifications,
            "gitlab": gitlab_notifications,
            "bugzilla": bugzilla_notifications,
            "obs": obs,
        }

    def ls(self):
        """Execute reading of individual requests."""
        # give an overview of different todo lists
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(v, self.args): k for k, v in self.dispatch.items()}
            try:
                for future in concurrent.futures.as_completed(futures, timeout=float(self.args.timeout)):
                    source = futures[future]
                    log.debug("result received for %s" % source)
                    try:
                        out_single = future.result()
                        if out_single:
                            print("\n".join(out_single))
                    except Exception as e:
                        log.error("%s failed: %s" % (source, e))
            except concurrent.futures.TimeoutError as e:
                log.info("requests could not complete in time: %s" % e)
                # Exiting hard with no cleanup as our access to different
                # services should be read-only anyway. If we do no stop
                # hard we might wait for a request which is not
                # terminating itself within an appropriate time.
                os._exit(1)


def load_config(config_path: str) -> Dict[str, Any]:
    config = configparser.ConfigParser()
    if os.path.exists(config_path):
        config.read(config_path)
    defaults = {}
    for section in config.sections():
        for key, value in config.items(section):
            defaults[key.replace("-", "_")] = value
    return defaults


def get_config_path_from_argv() -> str:
    for i, arg in enumerate(sys.argv):
        if arg in ("-c", "--config"):
            if i + 1 < len(sys.argv):
                return sys.argv[i + 1]
    return str(DEFAULTS["CONFIG_PATH"])


config_path = get_config_path_from_argv()
config_defaults = load_config(config_path)

app = typer.Typer(add_completion=False)


@app.command()
def main_command(
    cmd: str = typer.Argument(
        ...,
        help="The command to execute based on what todo.txt supports. The command is also passed to todo.txt as an underlying instance.",
    ),
    verbose: int = typer.Option(
        1,
        "-v",
        "--verbose",
        help="Increase verbosity level, specify multiple times to increase verbosity",
    ),
    config: Optional[str] = typer.Option(
        None,
        "-c",
        "--config",
        help="config file path",
    ),
    max_lines: int = typer.Option(
        int(config_defaults.get("max_lines", DEFAULTS["MAX_LINES"])),
        "--max-lines",
        help="Maximum number of lines for each output component",
    ),
    timeout: float = typer.Option(
        float(config_defaults.get("timeout", 3.0)),
        "-t",
        "--timeout",
        help="Timeout for overall processing. Returns what was retrieved until the timeout is hit.",
    ),
    github_username: Optional[str] = typer.Option(
        config_defaults.get("github_username"),
        "--github-username",
        help="Username for github access",
    ),
    github_token: Optional[str] = typer.Option(
        config_defaults.get("github_token"),
        "--github-token",
        help="OAuth2 token for github access",
        show_default=False,
    ),
    gitlab_host: Optional[str] = typer.Option(
        config_defaults.get("gitlab_host"),
        "--gitlab-host",
        help="gitlab server instance to query",
    ),
    gitlab_token: Optional[str] = typer.Option(
        config_defaults.get("gitlab_token"),
        "--gitlab-token",
        help="private token for API access (generate on your gitlab profile, Settings -> Access Tokens)",
        show_default=False,
    ),
    gitlab_merge_requests1: Optional[str] = typer.Option(
        config_defaults.get("gitlab_merge_requests1"),
        "--gitlab-merge-requests1",
        help="gitlab project for which open merge requests should be listed",
    ),
    bugzilla_host: Optional[str] = typer.Option(
        config_defaults.get("bugzilla_host"),
        "--bugzilla-host",
        help="bugzilla server instance to query",
    ),
    bugzilla_user: Optional[str] = typer.Option(
        config_defaults.get("bugzilla_user"),
        "--bugzilla-user",
        help="username on bugzilla instance used for authentication",
    ),
    bugzilla_password: Optional[str] = typer.Option(
        config_defaults.get("bugzilla_password"),
        "--bugzilla-password",
        help="password on bugzilla instance used for authentication",
        show_default=False,
    ),
    bugzilla_account: Optional[str] = typer.Option(
        config_defaults.get("bugzilla_account"),
        "--bugzilla-account",
        help="account name on bugzilla instance for identification, e.g. your email address",
    ),
    redmine_host: Optional[str] = typer.Option(
        config_defaults.get("redmine_host"),
        "--redmine-host",
        help="redmine server instance to query",
    ),
    redmine_token: Optional[str] = typer.Option(
        config_defaults.get("redmine_token"),
        "--redmine-token",
        help="private token for redmine API access",
        show_default=False,
    ),
    imap_host: Optional[str] = typer.Option(
        config_defaults.get("imap_host"),
        "--imap-host",
        help="IMAP email server to read TODO messages from",
    ),
    imap_username: Optional[str] = typer.Option(
        config_defaults.get("imap_username"),
        "--imap-username",
        help="username for IMAP email server",
    ),
    imap_password: Optional[str] = typer.Option(
        config_defaults.get("imap_password"),
        "--imap-password",
        help="password for IMAP email server",
        show_default=False,
    ),
) -> None:
    """
    medo: A meta-todo command-line application.

    Retrieves and lists todo items from various sources such as todo.txt,
    github, gitlab, bugzilla, redmine, email, and OBS.
    """
    _ = (cmd, verbose, config, max_lines, timeout)
    _ = (github_username, github_token, gitlab_host, gitlab_token)
    _ = (gitlab_merge_requests1, bugzilla_host, bugzilla_user, bugzilla_password)
    _ = (bugzilla_account, redmine_host, redmine_token)
    _ = (imap_host, imap_username, imap_password)


class ArgsNamespace:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)

    def __getattr__(self, name: str) -> Any:
        return self.__dict__.get(name)


def parse_args() -> Any:
    click_command = get_command(app)
    try:
        ctx = click_command.make_context("medo", sys.argv[1:])
        args = ArgsNamespace(**ctx.params)
    except BaseException as e:
        class_name = type(e).__name__
        if hasattr(e, "exit_code") and "Exit" not in class_name:
            click.echo(click_command.get_help(click.Context(click_command)), err=True)  # type: ignore
            click.echo(f"\nError: {e}", err=True)
            sys.exit(getattr(e, "exit_code"))
        if hasattr(e, "exit_code"):
            sys.exit(getattr(e, "exit_code"))
        if "Exit" in class_name:
            sys.exit(0)
        raise

    verbose_to_log = {
        0: logging.CRITICAL,
        1: logging.ERROR,
        2: logging.WARN,
        3: logging.INFO,
        4: logging.DEBUG,
    }
    logging_level = logging.DEBUG if args.verbose > 4 else verbose_to_log.get(args.verbose, logging.DEBUG)
    log.setLevel(logging_level)
    safe_args = {k: ("***" if ("token" in k or "password" in k) and v else v) for k, v in args.__dict__.items()}
    log.debug("args: %s" % safe_args)
    return args


def main() -> None:
    args = parse_args()
    medo = MeDo(args)
    medo.ls()


if __name__ == "__main__":
    main()
