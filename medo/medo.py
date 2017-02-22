#!/usr/bin/env python

# Python 2 and 3: easiest option
# see http://python-future.org/compatible_idioms.html
from __future__ import absolute_import
from future.standard_library import install_aliases  # isort:skip to keep 'install_aliases()'
install_aliases()

import certifi
import configargparse
import email
import email.header
import imaplib
import json
import logging
import os
import requests
import shutil
import subprocess
import sys
import urllib
from codecs import decode


DEFAULTS = {
    'MAX_LINES': 20,
    'CONFIG_PATH': os.path.expanduser('~') + '/.medorc',
    'CONFIG_USAGE': """
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
buzilla-account = me@example.com
""",
}

logging.basicConfig()
log = logging.getLogger(sys.argv[0] if __name__ == "__main__" else __name__)


def which(cmd):
    try:
        return shutil.which(cmd)
    except AttributeError:
        log.info('which method not (yet) available in shutil, reverting to workaround')
        x = subprocess.call(['which', cmd])
        return x == 0


def get_json(name, *args, **kwargs):
    """Retrieve JSON from a (REST) API server after checking correct response."""
    r = requests.get(*args, **kwargs)
    assert r.ok, "%s access failed: %s" % (name, r.reason)
    return r.json()


def gitlab_notifications(args):
    def get(route, base='api/v3/'):
        return get_json('gitlab', urllib.parse.urljoin(args.gitlab_host, base + route), headers={'PRIVATE-TOKEN': args.gitlab_token}, verify=certifi.where())

    todos = get('todos')
    gl = ['\n## gitlab %s' % args.gitlab_host] + todos
    # TODO do not have any todos right now

    if args.gitlab_merge_requests1:
        merge_requests_json = get('projects/%s/merge_requests' % urllib.parse.quote_plus(args.gitlab_merge_requests1) + '?state=opened')
        merge_requests = ['%s %s @%s' % (i['web_url'], i['title'], i['author']['name']) for i in merge_requests_json]
        gl += ['\n### gitlab merge requests %s' % args.gitlab_merge_requests1] + merge_requests
    return gl


def redmine_notifications(args):
    url = urllib.parse.urljoin(args.redmine_host, 'issues.json?limit=20&assigned_to_id=me')
    r = get_json('progress', url, auth=(args.redmine_token, ''))

    def ticket_str(i):
        return '%s +%s (%s) %s' % (args.redmine_host + str(i['id']), i['project']['name'], i['priority']['name'], i['subject'])

    redmine_issues = [ticket_str(i) for i in r['issues']]
    rm = ['\n## %s (%s issues)' % (args.redmine_host, r['total_count'])] + redmine_issues
    return rm


def bugzilla_notifications(args):
    """Get notifications from bugzilla instance.

    Reference: https://www.bugzilla.org/docs/4.4/en/html/api/Bugzilla/WebService/Bug.html#search
    """
    def get(method, params):
        r_params = {'method': method, 'params': json.dumps([params])}
        return get_json('bugzilla', urllib.parse.urljoin(args.bugzilla_host, 'jsonrpc.cgi'), auth=(args.bugzilla_user, args.bugzilla_password), params=r_params)

    def bug_str(bz_id, b):
        return ' '.join([bz_id + str(b['id']), b['product'], b['priority'], b['severity'], b['status'], b['summary']])

    assigned = get('Bug.search', {'assigned_to': args.bugzilla_account, 'resolution': ''})
    assigned_str = [bug_str(assigned['id'], i) for i in assigned['result']['bugs']]
    # another idea was to look for user as requestee but it looks like this is not accessible over current API
    bz = ['\n## bugzilla %s' % args.bugzilla_host] + assigned_str
    return bz


def obs(args):
    """OBS TODOs, pending reviews, submit requests."""
    log.debug('querying OBS TODOs')
    osc_my = subprocess.check_output(['osc', 'my'])
    osc_out = osc_my.splitlines()[:args.max_lines]
    osc = ['\n## OBS TODOs'] + osc_out
    osc_my_rq = subprocess.check_output(['osc', 'my', 'rq'])
    osc_out_rq = osc_my_rq.splitlines()[:args.max_lines]
    osc = ['\n### OBS requests'] + osc_out_rq
    return osc


def email_todos(args):
    imap = imaplib.IMAP4_SSL(args.imap_host)
    imap.login(args.imap_username, args.imap_password)
    imap.select('INBOX/todo')
    status, messages = imap.search(None, 'ALL')
    assert status == 'OK'
    msgs = [imap.fetch(i, '(BODY.PEEK[HEADER])') for i in messages[0].split()]
    emails = [email.message_from_string(decode(e[1][0][1], 'utf-8')) for e in msgs]
    mail_out = [' '.join([e['From'], e['Date'], e['Subject']]) for e in emails]
    email_str = ['\n## email TODOs (%s)' % len(mail_out)] + mail_out[:args.max_lines]
    return email_str


class MeDo(object):
    def __init__(self, args):
        """Construct object and save forwarded arguments."""
        self.args = args

    def ls(self):
        out = []
        # give an overview of different todo lists
        # * personal todo list
        if which('t'):
            t_ls_out = subprocess.check_output(['t', 'ls']).splitlines()
            out += ['\n## t (%s tasks)' % len(t_ls_out)] + [decode(line, 'utf-8') for line in t_ls_out][:self.args.max_lines]
        # * progress tasks
        if self.args.redmine_host:
            out += redmine_notifications(self.args)
        # * failing, unreviewed tests of SLE on osd
        # * failing, unreviewed tests on o3
        # * unread emails in inbox / todo emails
        if self.args.imap_host:
            out += email_todos(self.args)
        # * github notifications
        if self.args.github_token:
            github_auth = (self.args.github_username, self.args.github_token)
            r = get_json('github', 'https://api.github.com/notifications', auth=github_auth, headers={'Accept': 'application/vnd.github.v3+json'})
            gh = r[:self.args.max_lines]
            gh_out = sorted(['%s %s' % (i['subject']['url'].replace('https://api.github.com/repos', 'https://github.com'), i['subject']['title'],) for i in gh])
            out += ['\n## github'] + gh_out

        # * gitlab notifications
        if self.args.gitlab_host:
            out += gitlab_notifications(self.args)

        # * bugzilla tickets assigned to me, needinfo, etc.  * obs/ibs 'my'
        if self.args.bugzilla_host:
            out += bugzilla_notifications(self.args)

        # * submit requests in OBS/IBS
        if which('osc'):
            out += obs(self.args)

        print('\n'.join(out))

    def ls_waitfor(self):
        # * my own open github PRs
        # ...
        pass


def parse_args():
    parser = configargparse.ArgumentParser(formatter_class=configargparse.ArgumentDefaultsHelpFormatter, default_config_files=[DEFAULTS['CONFIG_PATH']])
    parser.add('-v', '--verbose', help="Increase verbosity level, specify multiple times to increase verbosity", action='count', default=1)
    parser.add('--max-lines', type=int, help="""Maximum number of lines for each output component""", default=DEFAULTS['MAX_LINES'])
    parser.add('--github-username', help="Username for github access")
    parser.add('--github-token', help="OAuth2 token for github access")
    parser.add('--gitlab-host', help="gitlab server instance to query")
    parser.add('--gitlab-token', help="private token for API access (generate on your gitlab profile, Settings -> Access Tokens)")
    parser.add('--gitlab-merge-requests1', help="gitlab project for which open merge requests should be listed")
    parser.add('--bugzilla-host', help="bugzilla server instance to query")
    parser.add('--bugzilla-user', help="username on bugzilla instance used for authentication")
    parser.add('--bugzilla-password', help="password on bugzilla instance used for authentication")
    parser.add('--bugzilla-account', help="account name on bugzilla instance for identification, e.g. your email address")
    parser.add('--redmine-host', help="redmine server instance to query")
    parser.add('--redmine-token', help="private token for redmine API access")
    parser.add('--imap-host', help="IMAP email server to read TODO messages from")
    parser.add('--imap-username', help="username for IMAP email server")
    parser.add('--imap-password', help="password for IMAP email server")
    parser.add('cmd',
               help="""The command to execute based on what todo.txt supports.
               The command is also passed to todo.txt as an underlying instance.""")
    parser.add('args', nargs=configargparse.REMAINDER, help="""All additional arguments are forwarded to any plugins or backends.""")
    args = parser.parse()
    verbose_to_log = {
        0: logging.CRITICAL,
        1: logging.ERROR,
        2: logging.WARN,
        3: logging.INFO,
        4: logging.DEBUG
    }
    logging_level = logging.DEBUG if args.verbose > 4 else verbose_to_log[args.verbose]
    log.setLevel(logging_level)
    log.debug("args: %s" % args)
    log.debug(parser.format_help())
    log.debug(parser.format_values())
    return args


def main():
    args = parse_args()
    medo = MeDo(args)
    medo.ls()

if __name__ == '__main__':
    main()
