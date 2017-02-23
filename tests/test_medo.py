"""
tests for medo.

isort:skip_file
"""

import pytest
import sys

from medo import medo  # SUT


def test_help():
    sys.argv += '--help'.split()
    with pytest.raises(SystemExit):
        medo.main()


def test_default():
    sys.argv[1:] = 'ls'
    medo.main()
