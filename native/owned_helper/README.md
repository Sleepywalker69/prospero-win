# Source-bound helper build inputs

The original root LICENSE is MIT. Preserve the file-level notices too: the shared
protocol header is LGPL-2.1-or-later. This mixed cohort is not MIT-only.
UPSTREAM.json records the recognized upstream source revision; REVIEWED-COHORT.json
binds the locally modified, separately reviewed helper inputs byte for byte.

The producer compiles the four listed C units using the supplied SDK and LLVM 18,
then performs static ELF/provider/entry checks. It never executes the target ELF.
Canonical metadata binds the source revision, exact source/header inventory,
compiler and SDK files, every compile/link/analyzer command, generated identity,
retained object files, link map, and final helper bytes. A consumed helper digest
must come from successful verification of those actual output bytes.

These records are integrity and source/build receipts, not signatures or proof of
source-to-binary reproducibility. They confer no console or lifecycle admission.
The dedicated initial-CANCEL title and the ordinary native title/full-CRT Wine
child build consume this producer through independent source/build admission.
The full cohort migration is documented in docs/matched-child-cohort.md.
No target launch is allowed until a version-bound, bounded no-reboot helper exit
and recovery route is established. HELD and CANCELLED receipts do not prove exit.
