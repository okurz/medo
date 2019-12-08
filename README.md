# medo [![Build Status](https://travis-ci.org/okurz/medo.svg?branch=master)](https://travis-ci.org/okurz/medo)

A meta-TODO script acting as a TODO list but interacting with multiple backends.

Commonly one has more than one TODO list, for example a manually maintained
list, emails that can be considered TODO items, tickets in issue trackers,
unread notifications and such. The goal of *medo* is to interact with all of
these backends using a single concise interface.


## Communication

If you have questions, contact me (*okurz*) irc.freenode.net, e.g. in
[#opensuse-factory](irc://chat.freenode.net/opensuse-factory).


## Contribute

This project lives in https://github.com/okurz/medo

Feel free to add issues in github or send pull requests.

TODOs and ideas are tracked in the file `TODO` as well as github issues.

### Rules for commits

* Every commit is checked by [Travis CI](https://travis-ci.org/travis) as soon as
  you create a pull request but you *should* run `tox` locally,

* It would be nice to keep the test coverage or increase it, e.g. by adding
  test reference data for new scenarios. TDD is advised :-)

* For git commit messages use the rules stated on
  [How to Write a Git Commit Message](http://chris.beams.io/posts/git-commit/) as
  a reference

If this is too much hassle for you feel free to provide incomplete pull
requests for consideration or create an issue with a code change proposal.

## License

This project is licensed under the MIT license, see LICENSE file for details.
