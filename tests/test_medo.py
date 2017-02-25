"""
tests for medo.

isort:skip_file
"""

import pytest
import sys
import subprocess

from medo import medo  # SUT


def test_help():
    sys.argv += '--help'.split()
    with pytest.raises(SystemExit):
        medo.main()


def test_default():
    sys.argv[1:] = 'ls'
    with pytest.raises(subprocess.CalledProcessError) as e:
        medo.main()
    assert 'non-zero exit status' in str(e)
