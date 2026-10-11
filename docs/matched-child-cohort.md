# Source-bound full launcher/child cohort

This integration replaces the legacy v0.3.2 helper release pin in the ordinary
native build and full-CRT Wine service-child build. It does not change target
runtime behavior, listeners, privileges, or transaction/HELD rules.

## Build and independent admission

1. Use one clean committed project source and the existing pinned foundations,
   public SDK and LLVM 18 toolchain. The owned-helper producer checks the reviewed
   source inventory and mixed MIT/LGPL notices before compiling.
2. Build the helper into a fresh directory outside source and SDK. Independently
   verify its retained source, commands, toolchain, objects, link map and actual
   ELF. No preselected replacement ELF hash exists.
3. Retain that evidence under `build/native<suffix>/owned-helper`. Generate the
   root `PW_LAPY_HELPER_SHA256` only from the verified final ELF bytes.
4. For the isolated full-CRT Wine fixture, pass that same directory via
   `--helper-directory`. The child revalidates source/project/protocol/toolchain
   and binds the actual helper digest in its generated header and recovered SELF.
   Its retained `owned-helper` directory supports independent replay.
5. Static title admission revalidates both evidence copies, the root compiled
   hash and exact compile definition, the embedded child SELF, original fixture,
   runtime ABI, provider/import graph and converter reconstruction. The service
   and title manifests use `/2`; old `/1` cohorts cannot pass the new admission.
6. The dedicated Windows-child packager carries the owned-helper receipts,
   objects/map/identity and original source/license evidence. It rejects legacy
   release sidecars or mixed root/child/helper metadata.

All generated metadata remains explicitly static-only. `runtime_validated` and
`console_execution_verified` remain false. These integrity receipts are neither
signatures nor proof of source-to-binary reproducibility.

## Remaining gates

No target build or console action was performed for this integration. Required:

- Commit/review the complete matched source, then compile helper, matched Wine
  runtime, full-CRT child and title using LLVM 18 and pinned dependencies.
- Independently replay all static admission and source/license/package checks on
  those exact outputs, with actual ELF/SELF digests.
- Establish the existing bounded, version-bound no-reboot helper recovery and
  process-lifecycle gate. A settled transaction, CANCELLED or HELD is not proof
  that the resident helper process has exited. Do not weaken ownership safety.
- Run the original same-byte Windows parent/child fixture through the launcher
  and full service-child route. A direct-worker result cannot substitute.
- Admit USER and network fixtures independently using their original references,
  then progress the matched I386 Battle.net route. Static capability declarations
  do not prove USER/input, TLS/network, CEF/graphics or Battle.net compatibility.

The generic `package_release.sh` path accepts `--owned-helper` and `--helper-sdk`
for independent admission before replacing its output, and retains exact helper
source/build/object/map/identity and mixed-license evidence. It still refuses
experimental private-dispatch runtimes; use the dedicated Windows-child packager
for that cohort. The native-probe suite verifier likewise consumes owned-helper
evidence and checks the compiled root helper digest, with a `/2` suite receipt.
