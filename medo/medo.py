#!/usr/bin/env python
import certifi
import configargparse
import json
import logging
import os
import requests
import subprocess
import sys
import urllib


DEFAULTS = {
    'MAX_LINES': 20,
    'CONFIG_PATH': os.path.expanduser('~') + '/.medorc',
    'CONFIG_USAGE': """
You are missing configuration file with the proper format.
Example:
...
""",
}

logging.basicConfig()
log = logging.getLogger(sys.argv[0] if __name__ == "__main__" else __name__)


def gitlab_notifications(args):
    def get(route, base='api/v3/'):
        r = requests.get(urllib.parse.urljoin(args.gitlab_host, base + route), headers={'PRIVATE-TOKEN': args.gitlab_token}, verify=certifi.where())
        assert r.ok, "gitlab access failed: %s" % r.reason
        return r.json()

    todos = get('todos')
    gl = ['\n## gitlab %s' % args.gitlab_host] + todos
    # TODO do not have any todos right now

    if args.gitlab_merge_requests1:
        merge_requests_json = get('projects/%s/merge_requests' % urllib.parse.quote_plus(args.gitlab_merge_requests1) + '?state=opened')
        merge_requests = ['%s %s @%s' % (i['web_url'], i['title'], i['author']['name']) for i in merge_requests_json]
        gl += ['\n### gitlab merge requests %s' % args.gitlab_merge_requests1] + merge_requests
    return gl

def bugzilla_notifications(args):
    def get(method, params):
        r_params = {'method': method, 'params': json.dumps([params])}
        r = requests.get(urllib.parse.urljoin(args.bugzilla_host, 'jsonrpc.cgi'), auth=(args.bugzilla_user, args.bugzilla_password), params=r_params)
        assert r.ok, "bugzilla access failed: %s" % r.reason
        return r.json()
    def bug_str(bz_id, b):
        return ' '.join([bz_id + str(b['id']), b['product'], b['priority'], b['severity'], b['status'], b['summary']])
    assigned = get('Bug.search', {'assigned_to': args.bugzilla_account, 'resolution': ''})
    assigned_str = [bug_str(assigned['id'], i) for i in assigned['result']['bugs']]
    bz = ['\n## bugzilla %s' % args.bugzilla_host] + assigned_str

    return bz

class MeDo(object):
    def __init__(self, args):
        """Construct object and save forwarded arguments."""
        self.args = args
        self.github_auth = (args.github_username, args.github_token)

    def ls(self):
        out = []
        # give an overview of different todo lists
        # * personal todo list
        t_ls_out = subprocess.check_output(['t', 'ls'])
        out += [line.decode('utf-8') for line in t_ls_out.splitlines()][:self.args.max_lines]
        # * progress tasks
        #https://progress.opensuse.org/issues.json?utf8=%E2%9C%93&set_filter=1&f[]=assigned_to_id&op[assigned_to_id]=%3D&v[assigned_to_id][]=17668&f[]=status_id&op[status_id]=o&f[]=&c[]=project&c[]=subject&c[]=status&c[]=assigned_to&c[]=fixed_version&c[]=is_private&c[]=due_date&c[]=relations&group_by=
        # * failing, unreviewed tests of SLE on osd
        # * failing, unreviewed tests on o3
        # * unread emails in inbox
        # * my own open github PRs
        # * github notifications
        r = requests.get('https://api.github.com/notifications', auth=self.github_auth, headers={'Accept': 'application/vnd.github.v3+json'})
        assert r.ok, "github access failed: %s" % r.reason
        gh = r.json()[:self.args.max_lines]

        gh_out = sorted(['%s %s' % (i['subject']['url'].replace('https://api.github.com/repos', 'https://github.com'), i['subject']['title'],) for i in gh])
        out += ['\n## github'] + gh_out

        # * gitlab notifications
        if self.args.gitlab_host:
            out += gitlab_notifications(self.args)

        # * bugzilla tickets assigned to me, needinfo, etc.  * obs/ibs 'my'
        if self.args.bugzilla_host:
            out += bugzilla_notifications(self.args)

        # * submit requests in OBS/IBS

        print('\n'.join(out))


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
