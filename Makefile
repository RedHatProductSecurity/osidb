############################################################################
## Introduction
############################################################################



# Run 'make help' to display a summary of all targets!



# If you edit this Makefile, please observe these code style rules:
#
# * Targets that are not based on real files should be .PHONY (see
#   https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html).
#
# * Mark sections with major topics with comments starting with two `##`.
#   Document each target or group of closely related targets with comments
#   starting with three `###`. Test help display with `make help`.
#
# * Notice that 'make' aborts whenever a command returns a non-zero exit code.
#
# * All actions should be runnable without active venv. If a targets needs
#   venv, it should activate it itself.



#***********************************
### Print summary of Makefile targets
#***********************************
.PHONY: help
help:
	@cat Makefile mk/*.mk | grep -E '(^###? )|(^[a-zA-Z][a-zA-Z_.-]+:)' | sed -r "s/^(^[a-zA-Z][^:]+):.*/    $$(printf '\033')[1m\1$$(printf '\033')[0m/g" | sed -r "s/^## (.*)/\n$$(printf '\033')[4m$$(printf '\033')[3m$$(printf '\033')[1m\1$$(printf '\033')[0m\n/" | sed -r "s/^### (.*)/\n  $$(printf '\033')[3m\1$$(printf '\033')[0m/" | sed -z 's/\n\n\n/\n\n/g' | less -R



include mk/*.mk
