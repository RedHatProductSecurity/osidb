# OSIDB -- operations

## Code freeze

At least one week before the intended release date, the main development branch should be frozen into
a release-X.Y.Z branch, where X.Y.Z is the next intended release version.

You can do it like so:

```bash
git checkout master
git pull
git checkout -b release-X.Y.Z
git push origin release-X.Y.Z
```

Only bug fixes should be merged into this new branch, and they should be done so via PRs that target
the release branch so that the code can be reviewed.

Make sure that the stage environment is set to pull from this branch at least until it is merged
back into the main development branch.

## Release

Follow this procedure when performing OSIDB version X.Y.Z release, this step assumes that
the previous step on code freezing has already been done.

First we need to determine the version number based on the previous version
and the changes to be released - see [Versioning](#Versioning).

```bash
git diff $(git describe --tags --abbrev=0) openapi.yml
```

Make sure you perform the following commands from the project root directory.

```bash
git checkout release-X.Y.Z
git checkout -b release-X.Y.Z-prep
scripts/update_release.sh X.Y.Z
```

This script will also change some things in the operations repository, those should
also be submitted via a PR to the appropriate repository and merged after tag creation.

Check and eventually update [CHANGELOG](../CHANGELOG.md).

```bash
git commit -am 'Update version to X.Y.Z'
git push -u origin release-X.Y.Z-prep
```

And then submit `release-X.Y.Z-prep` as a PR against the `release-X.Y.Z` branch.

Next, create a tag based off of the `release-X.Y.Z` branch, you can do this via git
but it's preferable to do it via the [releases](https://github.com/RedHatProductSecurity/osidb/releases) page on GitHub,
this page lets you create a new tag to go with the release, the Changelog should be copied
into the release's description, this release link can then be used for new release announcements.

Now you need to either wait for the tag to sync back into GitLab (~30min) or force a manual sync
from the GitLab settings (Settings > Repository > Mirrors), at this point the changes in the
operations repo can be merged and the changes can be deployed.

Finally, once everything has been correctly deployed, make sure to create a PR against the
main development branch in which the source is the `release-X.Y.Z` branch, to guarantee that
the next versions include any bugfixes that were in the frozen branch.

## Scripts

Descriptions of the scripts located in the `scripts` directory

### update_release.sh

Updates OSIDB version in all places. Run it from project root directory with X.Y.Z being the target version.

```
scripts/update_release.sh X.Y.Z
```

## Custom management commands

### syncflaws

`syncflaws` is a custom Django management command that allows developers to
manually force the sync of one or more flaws by providing their Bugzilla ID.

To use it, simply pass any amount of Bugzilla IDs as positional arguments:

```bash
$ python3 manage.py syncflaws 12345 815873 2111111
```

The output will look like so:

```bash
Synchronizing 12345...OK
Synchronizing 815873...FAIL
Synchronizing 2111111...FAIL
```

This management command supports the default `-v` or `--verbosity` Django
management command option:

* `-v 0` and `-v 1` are equivalent (and the latter is the Django default).

* `-v 2` provides the error message of the exception raised for a particular
  flaw sync, so if the error raised is e.g. `ValidationError("Foo!")` the
  command will print `Exception: Foo!` right after the status.

* `-v 3` provides the full traceback of any hard exceptions as well as any
  logging done by the sync process itself.

## Versioning

OSIDB uses [Semantic Versioning](https://semver.org/). We start versioning with 0.0.1.
Additionally, we consider OSIDB 1.0.0 as the first General Availability version.

To update OSIDB to a new version use [scripts/update_release.sh](../../scripts/update_release.sh).
