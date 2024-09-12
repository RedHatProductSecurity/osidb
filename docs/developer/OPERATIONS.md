# OSIDB -- operations

## Release

The release process consists of multiple phases and usually takes at least a week.
Therefore, it needs to be properly planned and communicated. Currently, there is no
regular release schedule. The release is planned when the team decides so.

Exceptionally, it may happen that a critical issue which blocks the users to perform
their duties is found. In such case the phases of the release may be shortened as
needed but due to the reduced space for the testing and communication it requires
an extreme caution.

> [!CAUTION]
> A major release should never be done in haste.

### Branching

At least one week before the intended release date, `master` branch should
be branched into a release branch. Start with

```bash
git checkout master
git pull
```

Then, determine the next release version number based on the previous version
and the changes to be released - see [Versioning](#Versioning). Run

```bash
git diff $(git describe --tags --abbrev=0) openapi.yml
```

The general decission procedure is as follows.

- If there are no changes shown, increase the patch version number.
- If there are only additions, increase the minor version number.
- If there are any removals, increase the major version number.

> [!TIP]
> There may be exceptions like experimental API endpoints or data changes which do not
> fully reflect in the API documentation. It is therefore advised to always ask another
> experienced developer to double check the correct versioning.

With the resulting version number `X.Y.Z` perform

```bash
git checkout -b release-X.Y.Z
git push origin release-X.Y.Z
```

Make sure you perform the following commands from the project root directory.

```bash
git checkout release-X.Y.Z
git checkout -b release-X.Y.Z-prep
scripts/update_release.sh X.Y.Z
```

Check and eventually update [CHANGELOG](../CHANGELOG.md). If everything looks OK

```bash
git commit -am 'Update version to X.Y.Z'
git push -u origin release-X.Y.Z-prep
```

and submit `release-X.Y.Z-prep` as a PR against the `release-X.Y.Z` branch.
After the review is successfully finished and the PR is merged, the release branch is ready.
You can continue with [UAT](#UAT) phase.

### UAT

Deploy the `release-X.Y.Z` branch to the **UAT** environment - the details on
the deployment procedure can be found in the OPS repository documentation.
Announce the upcoming release to the users and ask them to test their
workflows or integrations using the **UAT** environment.

> [!IMPORTANT]
> In the case of major release it is necessary to namely announce all the breaking
> changes and expressly ask the owners of all the known integrations to account for
> them to prevent any posible breakage. It may happen that some of them will
> require an extended adoption period especially if the changes are significant.

Gather the feedback over time and fix the reported bugs with priority.
This pre-release testing period should last at least one week or as long as needed
to fix all the newly reported bugs not to introduce any regression.

> [!NOTE]
> At this point only bug fixes should be added into the release branch.
> Use `git cherry-pick` to keep it in sync with `master`.

### Production

After the successful [UAT](#UAT) phase, it is time for the production release.
Put together the release announcement in advance so it can be sent right after the
release. Announce to the users that there may be a short period of production
unavailability due to the pod deployment.

Create an `X.Y.Z` tag based off of the `release-X.Y.Z` branch via the
[releases](https://github.com/RedHatProductSecurity/osidb/releases) page on GitHub.
The Changelog should be copied into the release's description so its release link
can then be used for the new release announcements. The production deployment
should then happen automatically which can be observed by the changed version
shown at the WebUI - consult the OPS repository documentation otherwise.

Once everything has been correctly deployed, send the release announcement.
Finally, make sure to create a PR against `master` branch in which the source
is the `release-X.Y.Z` branch, to guarantee that the next versions include
 the correct [CHANGELOG](../CHANGELOG.md).

## Makefile

Number of useful operational commands is provided by the `make` utility.
Run the following command in the repository root directory to get further documentaion.

```bash
$ make help
```

## Scripts

Descriptions of the scripts located in the `scripts` directory

### update_release.sh

Updates OSIDB version in all places. Run it from project root directory with X.Y.Z being the target version.

```
scripts/update_release.sh X.Y.Z
```

## Custom management commands

### check_sync

Quickly check the status of the sync managers.

```bash
$ python3 manage.py check_sync
```

### sync_jira_metadata

Synchronize the Jira projects' metadata on demand.

```bash
$ python3 manage.py sync_jira_metadata
```

### sync_product_definitions

Synchronize the product definitions on demand.

```bash
$ python3 manage.py sync_product_definitions
```

### sync_ps_constants

Synchronize the PS constants on demand.

```bash
$ python3 manage.py sync_ps_constants
```

### syncflaws

> [!CAUTION]
> Bugzilla is already a secondary source of flaw data and can be incomplete.
> The sync from there may potentially lead to a data loss.

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
The list of released versions can be found
[here](https://github.com/RedHatProductSecurity/osidb/tags) - except those preceding the repository migration.

To update OSIDB to a new version use [scripts/update_release.sh](../../scripts/update_release.sh).
