# project justfile

import? '.just/compliance.just'
import? '.just/gh-process.just'
import? '.just/pr-hook.just'
import? '.just/shellcheck.just'
import? '.just/cue-verify.just'
import? '.just/claude.just'
import? '.just/copilot.just'
import? '.just/repo-toml.just'
import? '.just/template-sync.just'

# list recipes (default works without naming it)
[group('Utility')]
list:
	just --list
	@echo "{{GREEN}}Welcome to gh-amp!{{NORMAL}}"

# install the extension locally for testing
[group('Development')]
install:
	gh extension install .

# uninstall the local extension
[group('Development')]
uninstall:
	-gh extension remove gh-amp

# run amp locally (without installing)
[group('Development')]
run *ARGS:
	./gh-amp {{ARGS}}

# run shellcheck on the extension script
[group('Quality')]
shellcheck-amp:
	shellcheck -x -s bash gh-amp

# dev cycle
[group('Development')]
build: shellcheck-amp uninstall && install
	# all in header

# test list
[working-directory: '../gh-observer/']
[group('Development')]
test_list:
	gh amp list

# test review
[working-directory: '../gh-observer/']
[group('Development')]
test_review:
	gh amp review
