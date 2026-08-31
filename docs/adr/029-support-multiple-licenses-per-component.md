| Status   | Date       | Author(s)                                                |
|:---------|:-----------|:---------------------------------------------------------|
| Proposed | 2026-08-31 | [@cartermitchellLM](https://github.com/cartermitchellLM) |

## Context

Presently in the tool, a component is by default considered to have one license associated to
it if it is not utilizing SPDX License Expressions. The default selection is done by taking the
first license present in the imported BOM and discarding the rest. This is limiting in that some
tools do have multiple licenses that apply and not every user uses SPDX License Expressions. It
is also unclear to users that this is being done. Losing that data is not ideal, so it should be
persisted more accurately for user awareness.

## Decision

Extracting the licenses data associated to a component into its own table will solve this data loss. 
There is already precedence for doing so with vulnerabilities (see: the `COMPONENTS_VULNERABILITIES`
table), though this will allow an expansion of functional data. The `COMPONENTS` table will lose
its license related columns as well as its foreign key constraint to the `LICENSE` table, shifting
them all to a table called `COMPONENTLICENSES`.

The `COMPONENTLICENSES` will house all of that old data with the addition of two columns: `CONCLUDED` 
and `ORDINALITY`. The `CONCLUDED` column will allow for future implementation of users accepting 
licenses as concluded, but presently will populate by default with a value of `false`. The `ORDINALITY`
column will preserve the current functionality of assuming the licenses coming from the BOM are ordered.

Changes to the frontend will be made alongside this database shift that will allow users to view all of
a component's licenses through the addition of a new API endpoint that fetches all of them.

## Consequences

The API will have an endpoint added to it, causing a minor version upgrade to support 
the more detailed license information being available to users.

Most of these changes are not user facing, but will allow for easier implementation of future
license related features.
