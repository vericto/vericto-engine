# License history

This file identifies the license boundary of published `vericto-engine` source.
It is part of the release record. A Git author or committer date alone is not
proof of when source was first made available.

## Current and planned license

| Source | License |
|---|---|
| Tag `v5.0.0` and later releases, beginning with the transition represented by this working tree | GNU Affero General Public License, version 3 only (`AGPL-3.0-only`), or a separate commercial license from Vericto S.A.S. |
| Tags `v4.3.0` through `v4.7.1` | Functional Source License, Version 1.1, ALv2 Future License (`FSL-1.1-ALv2`) |
| Tag `v4.2.0` and earlier releases | Elastic License 2.0 (`Elastic-2.0`) |

The last FSL release is:

- tag: `v4.7.1`;
- commit: `64e13ef36631ddecf15f9ba4862642e00bbed109`;
- first documented public availability: 2026-11-01 (UTC), through pull request 58.

The first AGPL release will be identified by tag `v5.0.0`. The tag itself is
the immutable mapping to its commit SHA. Create and publish that tag at the
same time as the release. Do not publish an artifact called `4.7.1` from the
AGPL working tree.

## FSL future-license schedule

FSL 1.1 grants Apache License 2.0 for each version on the second anniversary of
the date Vericto first made that version available. The following dates use
the creation time of the public pull request as the earliest retained evidence
for each tagged release line. If Vericto finds earlier public evidence for a
specific commit or artifact, that earlier date controls for that version.

| Release | Commit | Documented public date (UTC) | Apache 2.0 no later than |
|---|---|---:|---:|
| `v4.3.0` | `7382d68fde4e174cc5c7cd5204dc065ac7f6ffa4` | 2026-10-19 | 2028-10-19 |
| `v4.4.0` | `db651b6c3c5b645ec62f4546ac10b6b236ca86e1` | 2026-10-22 | 2028-10-22 |
| `v4.5.0` | `b1da287ff77cff1153abbfd54fdbad5ba22a0a91` | 2026-10-24 | 2028-10-24 |
| `v4.6.0` | `e986d8b2eb1f23dd688ee9a4bd138fb114e98bc2` | 2026-10-25 | 2028-10-25 |
| `v4.7.0` | `c24ae9d05a604711e85b4613764c2fa818f4d421` | 2026-10-31 | 2028-10-31 |
| `v4.7.1` | `64e13ef36631ddecf15f9ba4862642e00bbed109` | 2026-11-01 | 2028-11-01 |

This table lists tagged releases. An intermediate FSL commit or package may
have its own date because FSL defines the Software as each version made
available with its terms. Preserve pull-request, package and release records.
Do not infer the legally effective date only with `git rev-list --before`.

The controlling license text remains the `LICENSE` file distributed with each
version. For example:

```sh
git show v4.7.1:LICENSE
git show v4.2.0:LICENSE
```
