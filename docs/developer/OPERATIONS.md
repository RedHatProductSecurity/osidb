# OSIDB -- operations

## Release

Follow this procedure when performing OSIDB version X.Y.Z release.
First we need to determine the version number based on the previous version
and the changes to be released - see [Versioning](#Versioning).

```bash
git diff $(git describe --tags --abbrev=0) openapi.yml
```

Make sure you perform the following commands from the project root directory.

```bash
git checkout master
git pull
git checkout -b release-X.Y.Z
scripts/update_release.sh X.Y.Z
```

Check and eventually update [CHANGELOG](../CHANGELOG.md).

```bash
git commit -am 'Update version to X.Y.Z'
git push -u origin release-X.Y.Z
```

Create a merge request and ask for review. Merge it when approved.

```bash
git checkout master
git pull
git tag X.Y.Z
git push --tags
```

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
