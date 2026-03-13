# Contributing
OSIDB is an open initiative and we welcome any help.
Before contributing please read and follow these guidelines.

## How to contribute to OSIDB

### Did you find a bug?

* Ensure the bug was not already reported by searching on GitHub under
  [Issues](https://github.com/RedHatProductSecurity/osidb/issues).

* If you're unable to find an open issue addressing the problem:

  * If you are [Red Hat](https://www.redhat.com/) associate and you are requesting company specific
    functionality open a new issue
    [here](https://uat-3-2-redhat.atlassian.net/secure/CreateIssueDetails!init.jspa?pid=12332734&issuetype=1).

  * Otherwise open a new issue [here](https://github.com/RedHatProductSecurity/osidb/issues/new).

* Be sure to include a title and clear description, as much relevant information as possible,
  and a comand line or code sample or an executable test case demonstrating the
  expected behavior that is not occurring.

### Did you fix whitespace, format code, or make a purely cosmetic patch?

Changes that are cosmetic in nature and do not add anything substantial to the stability,
functionality, or testability of the project will generally not be accepted.

### Did you write a patch?

* Open a new GitHub pull request with the patch.

* Ensure the PR description clearly describes the problem and solution.

* Include the relevant issue number if applicable. There is a Jira automation
  which changes the state of the mentioned Jira issues accordingly. Expected
  format of the issue mention starts with word `Closes` or `Fixes` (**C or F must be uppercase**)
  followed by a Jira ID:

  ```
  Closes OSIDB-111
  ```
  OR
  ```
  Fixes OSIDB-111
  ```

  To mention multiple Jira IDs, you need to use multiple keywords:

  ```
  Closes OSIDB-111
  Closes OSIDB-222
  Fixes OSIDB-333
  ```

  Creating or editing a PR which mentions the Jira issues will transfer the status of all the mentioned Jira issues
  to **Review**.

  Closing a PR which sets the status of PR to merged will transfer the status of all the mentioned Jira issues to
  **Release Pending** and change the Fix Version field to **OSIDB-next**.

* Before submitting make sure that linters and tests are passing.
  Details on running the test can be found [here](DEVELOP.md#run-tests).
  Also make sure that the CI pipelines report success in the PR.

* The OSIDB repository requires that all commits be GPG-signed, see
  [GitHub's documentation](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)

* Given that signed commit are required, the git flow might be different than
  what you're used to, one of the limitations is that only merge commits
  can be used from the PR interface, this in turn means that you should make sure
  your branch is clean and up-to-date, by clean we mean that **no** merge commits
  should be included in your patchset and the changes should be rebased on top of
  the latest master (i.e. `git pull --rebase origin master`).

* All commit messages should follow the classic git flow recommendations as seen
  in the Git SCM [documentation](https://git-scm.com/book/en/v2/Distributed-Git-Contributing-to-a-Project#-commit-guidelines)

* All functional changes require an entry in the [CHANGELOG](docs/CHANGELOG.md)
  that describes the change and a reference to a JIRA issue if any, a GitHub
  action will check that the file has been updated. If your change is purely
  technical, you can add or request someone to add the "technical" label to the
  Pull Request, which will skip the check.

### Do you have questions about the source code?

We unfortunately do not have a publicly accessible discussion channel yet.
You can create an issue [here](https://github.com/RedHatProductSecurity/osidb/issues/new)
and ask your question within.

## License
All contributions to this project will be licensed under [MIT](../../LICENSE) license.
By contributing you agree that your all submissions are also licensed under this license.

## Reference

These guidelines were strongly inspired by Ruby on Rails project
[contributing](https://github.com/rails/rails/blob/main/CONTRIBUTING.md) guidelines.
