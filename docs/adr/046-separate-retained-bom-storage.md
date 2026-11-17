| Status   | Date       | Author(s)                                                |
|:---------|:-----------|:---------------------------------------------------------|
| Proposed | 2026-11-16 | [@elias-chevere-lm](https://github.com/elias-chevere-lm) |

## Context

Dependency-Track stores large files, such as uploaded BOMs, in file storage ([ADR 004]).
Each deployment uses one storage provider with one location, either one S3 bucket or one
local directory. By default, the encryption keys and all stored files are in the same data
directory, usually on one volume. The stored files are BOM and VEX uploads, files for
vulnerability analysis, and notifications. Most of them are temporary. They are deleted
when their workflow finishes.

[ADR 045] adds opt-in retention of the original BOM. A retained BOM is the uploaded file
itself. It stays in storage after the import, until a retention policy or the deletion of
its project removes it. Today, retained and temporary uploads both use the same name,
`bom-upload/<upload token>`. Only the database can tell them apart.

Retained BOMs can grow quickly. If operators do not plan enough space, the storage fills up,
and all uploads fail, not only retained ones. Today, operators also cannot measure, limit,
or back up retained BOMs apart from temporary files without querying the database.

Not every deployment wants a second bucket or volume, because it adds infrastructure and
cost. A separate location must therefore be optional. Without it, Dependency-Track must
behave as it does today.

[ADR 004] describes file storage as a simple key-value store. This stays true. This decision
adds a second location, not new storage capabilities.

This is a new ADR and not a follow-up. It builds on [ADR 045], but it does not change its
decision. A retained BOM is still the uploaded file, and there is still only one copy. Only
the place where the file is written changes. The change also affects file storage
([ADR 004]), and it has its own alternatives and trade-offs that need their own review. So
it does not belong to either ADR alone. Also, follow-ups extend accepted ADRs, and
ADR 045 is still proposed.

### Possible Solutions

#### A: Configuration only

Operators move all file storage to its own volume or bucket with the existing settings.

*Pros*:

1. No code change is needed.
2. It is possible today.

*Cons*:

1. Retained BOMs and temporary files still share one location.
2. Operators still cannot measure, limit, or back up retained BOMs on their own.
3. Retained and temporary uploads still have the same names.

#### B: Name prefix only

The `apiserver` gives retained uploads the name prefix `retained-bom/`. All files stay in
one location.

*Pros*:

1. The change is very small, and there is no new setting.
2. Operators can tell retained BOMs apart by their name. They can measure the size of the
   prefix, and S3 lifecycle rules can filter by prefix.

*Cons*:

1. Retained BOMs still share one volume or bucket with all other files.
2. Bucket metrics, quotas, backup, replication, and versioning still apply to all files together.
3. When the volume is full, all uploads still fail.

#### C: Name prefix with one optional setting per provider

The `apiserver` uses the name prefix from option B. The S3 and local providers each get one
optional setting. When it is set, the provider writes files with the prefix to a separate
bucket or directory.

*Pros*:

1. Operators can use a separate bucket or volume when they need one.
2. When the setting is unset, the behavior is the same as option B.
3. The storage interface, the database schema, and the REST API do not change.
4. Each setting is a single value, so it maps to one environment variable.

*Cons*:

1. The S3 and local providers must know one name prefix that the `apiserver` uses.
2. On local storage, operators must move files when they change the setting.
3. With S3, the credentials need access to both buckets.

#### D: One provider-neutral setting with routing in the `apiserver`

One setting that does not depend on the provider names the second location. The `apiserver`
creates a second storage instance for retained BOMs, and picks the instance by file name.

*Pros*:

1. The providers do not need to know the prefix.

*Cons*:

1. The `apiserver` must know which provider setting to replace: the bucket for S3, or the
   directory for local storage. This couples it to the configuration of each provider.
2. The application runs two storage instances, for example two S3 clients.

#### E: General mapping from name prefix to location

A setting maps any name prefix to its own bucket or directory.

*Pros*:

1. It could also cover future needs, for example a separate location for VEX uploads.

*Cons*:

1. Each entry needs at least two values. This does not map well to environment variables.
2. It needs more validation, for example for prefixes that overlap.
3. No use case needs it today.

## Decision

We will follow option C.

When retention is enabled at upload time, the `apiserver` will name the upload
`retained-bom/<project UUID>/<upload token>`. Other BOM uploads keep the name
`bom-upload/<upload token>`. The project UUID groups the files of one project, so operators
can see how much space each project uses. The upload token is time-based, so file names
still contain the creation time, as [ADR 004] recommends.

The S3 provider will get the optional setting `dt.file-storage.s3.retained-bom-bucket`.
When it is set, the provider writes files with the `retained-bom/` prefix to this bucket.
It uses the same endpoint and credentials as for the main bucket. Reads and deletes keep
using the bucket that is part of the stored file location.

The local provider will get the optional setting
`dt.file-storage.local.retained-bom-directory`. When it is set, the provider writes files
with the `retained-bom/` prefix below this directory. The prefix stays part of the path, for
example `<retained directory>/retained-bom/<project UUID>/<upload token>`. The stored file
location stays relative, for example `local:///retained-bom/<project UUID>/<upload token>`.
For reads and deletes, the provider uses the prefix to pick the directory. It will not look
in both directories.

When a setting is unset or empty, all files stay in the main bucket or directory. Retained
BOMs still use the `retained-bom/` prefix there.

Both providers will check the setting at startup and fail when it is not valid. The S3
provider checks that the retained bucket exists and that it is not the main bucket. The
local provider creates the retained directory when it is missing, and checks that it can
read and write it. The retained directory must not be the main directory, and neither
directory may be inside the other. The local provider uses both directories as absolute,
normalized paths, so relative paths and paths that contain `..` work as expected. When both
directories are on the same filesystem, the local provider logs a warning. This often means
that the volume for retained BOMs was not mounted.

The settings are not required when retention is enabled. Retention is a runtime setting in
the database, and an unset storage setting is a valid configuration.

The storage interface, the database schema, and the REST API will not change. The in-memory
provider will not change. VEX uploads, vulnerability analysis files, and notifications stay
in the main location. Moving existing files and a general mapping of prefixes to locations
(option E) are out of scope.

## Consequences

Operators can measure, limit, and back up retained BOMs apart from other files. The sizes
they see are compressed sizes. Both providers compress files, so stored files are smaller
than the uploaded BOMs.

The S3 and local providers now know one name prefix of the `apiserver`. This is a small
coupling between the application and storage. [ADR 045] decided against a new lookup
operation in the storage interface, because every provider would inherit a new contract.
This decision adds no operation and does not change the interface. Routing stays optional.
A provider without it, such as the in-memory provider, keeps retained BOMs under the prefix
in its only location.

Deployments without either setting keep one location. In that case, the only change is the
new name prefix for retained BOMs.

When the retained location has its own capacity, for example its own volume or a bucket with
its own quota, a full retained location only makes BOM uploads with retention enabled fail.
Other uploads and features are not affected. A separate directory on the same filesystem, or
a separate bucket on the same storage server, does not provide this isolation.

An upload with retention enabled is written to the retained location before its import
runs. Imports that are still running or that failed are therefore counted there for a short
time. A failed import deletes its upload as described in [ADR 045].

Lifecycle rules for the main bucket, for example to remove orphaned temporary files as
[ADR 004] suggests, no longer need to exclude retained BOMs. This is only true once no
retained BOMs remain in the main bucket.

With S3, the bucket is part of the stored file location. When the setting is added or
changed, existing files stay readable and deletable in the bucket where they were written.
New retained BOMs go to the new bucket. The credentials need access to every bucket that
still holds retained BOMs.

On local storage, the stored file location does not name the directory. When the setting is
added or changed, the provider looks for existing retained BOMs in the new directory.
Operators must move the files when they change the setting. They stop Dependency-Track,
move the `retained-bom` directory from the old location into the new directory, change the
setting, and start Dependency-Track again. Changing the main directory already works the
same way today. If operators do not move the files:

* The endpoint returns not found for the latest retained BOM of the affected projects, until
  the files are moved.
* Imports with retention enabled that had not finished before the restart fail, and they do
  not retry.
* Retention cleanup and project deletion still remove their references as usual. They cannot
  delete the files in the old location, so these files stay there as orphans.

[ADR 004]: ./004-file-storage-plugin.md
[ADR 045]: ./045-retain-original-bom-files.md
