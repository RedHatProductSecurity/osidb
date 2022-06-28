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

Check and eventually update [CHANGELOG](docs/CHANGELOG.md).

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

## Versioning

OSIDB uses [Semantic Versioning](https://semver.org/). We start versioning with 0.0.1.
Additionally, we consider OSIDB 1.0.0 as the first General Availability version.

To update OSIDB to a new version use [scripts/update_release.sh](../scripts/update_release.sh).
