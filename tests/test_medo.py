"""
tests for medo.

isort:skip_file
"""

# see http://python-future.org/compatible_idioms.html
from future.standard_library import install_aliases  # isort:skip to keep 'install_aliases()'
from future.utils import iteritems

install_aliases()

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
