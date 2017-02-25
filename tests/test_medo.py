"""
tests for medo.

isort:skip_file
"""

import os.path
import pytest
import sys

from medo import medo  # SUT


def test_help():
    sys.argv += '--help'.split()
    with pytest.raises(SystemExit):
        medo.main()


def test_default(mocker):
    sys.argv[1:] = ['-c', os.path.join(os.path.dirname(__file__), 'medorc'), 'ls']
    args = medo.parse_args()
    mocker.patch('requests.get')
    mocker.patch('subprocess.check_output')
    mocker.patch('subprocess.call')
    args.timeout = 1
    args.imap_host = None
    m = medo.MeDo(args)
    m.ls()
