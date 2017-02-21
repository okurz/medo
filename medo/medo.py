#!/usr/bin/env python
import subprocess

T_MAX_LINES = 20
t_ls_out = subprocess.check_output(['t', 'ls'])
t_first = [line.decode('utf-8') for line in t_ls_out.splitlines()][:T_MAX_LINES]

# give an overview of different todo lists
# * personal todo list
print('\n'.join(t_first))
# * progress tasks
#https://progress.opensuse.org/issues.json?utf8=%E2%9C%93&set_filter=1&f[]=assigned_to_id&op[assigned_to_id]=%3D&v[assigned_to_id][]=17668&f[]=status_id&op[status_id]=o&f[]=&c[]=project&c[]=subject&c[]=status&c[]=assigned_to&c[]=fixed_version&c[]=is_private&c[]=due_date&c[]=relations&group_by=
# * failing, unreviewed tests of SLE on osd
# * failing, unreviewed tests on o3
# * unread emails in inbox
# * my own open github PRs
# * github notifications
