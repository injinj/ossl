# AGENTS.md — ossl

Open SSL — the Reuters "Source Sink Library" 4.x sink protocol (Triarch /
RMDS / RTDS `rmds_ssl_sink`, port 8101) that SSL SDK, RFA 7.x SSLED, SFC
and ADS-POP consumers speak. `ossl_server` fronts an OMM (RSSL)
infrastructure with an SSL distributor so those consumers keep working
after LSEG removes Marketfeed/SSL from RTDS; `ossl_client` is an SSL 4.5
sink client. The wire protocol was derived from captures and is written
up in `docs/PROTOCOL.md` — read it before touching `ipc.cpp`. Namespace
`rai::ossl`. Depends on raikv, raimd, libdecnumber, omm.

## Workspace layout (injinj fleet convention)

- This repo is one of the `injinj` siblings. Every dependency is a sibling
  checkout (`../raikv`, `../raimd`, `../libdecnumber`, `../omm`); headers come from
  `-I../<dep>/include` and libraries from
  `../<dep>/FC43_x86_64/lib64/lib<dep>.a`. There is no install step between
  siblings — build the dependency, then build this repo.
- Dependencies are declared once, in `build_depends.mak`
  (`<dep>_dep := MAJOR.MINOR`, the rpm BuildRequires minimum). `./deps.sh`
  clones missing siblings from it, `./deps.sh -b` also builds them in
  dependency order, `./deps.sh -s` prints the commit of this repo and every
  sibling (the only record of what a release was built from).
- Whole-fleet build order lives in `~/injinj/GNUmakefile` (`make build`):
  openpgm → raikv → libdecnumber → raimd → linecook → lzf → rdbparser → h3 →
  HdrHistogram_c → sassrv → raids → natsmd → omm → raims → rvcache →
  raimdapi → ossl.

## Build

- `make` → `FC43_x86_64/bin`, `FC43_x86_64/lib64`. The build dir is
  `$(short_dist)$(lsb_dist_ver)_$(uname_m)$(port_extra)`: Fedora 43 →
  `FC43_x86_64`, Rocky 9.5 → `ROCKY9.5_x86_64`.
- `make port_extra=-g` → debug build in `FC43_x86_64-g`.
  `make port_extra=-mingw` → Windows cross build in `FC43_x86_64-mingw`
  (mingw64 toolchain; links the siblings' *master* checkouts).
- `NO_STL=1` builds with `-fno-rtti -fno-exceptions` and links with the C
  compiler; library code is written to survive that (error returns, no
  exceptions, no RTTI). Keep it that way.
- `make -j8` is safe; the makefile dependencies are complete. One trap: the
  **first `-j` run right after a compile error** can fail test executables
  with bogus undefined references (symbols from this repo's own lib)
  because they link against a library left half-updated by the failed run.
  Run plain `make` once, then `-j` works again. It is not a missing
  dependency.
- Warnings are clean. A new warning is a defect.
- If a sibling's public headers changed, rebuild the sibling first. A link
  warning like `lib<dep>.so.1.N, needed by ../<x>/.../lib<x>.so, not found`
  means sibling `<x>` was built against an older `<dep>` — rebuild `<x>`;
  at run time that warning is a hard failure.
- Ad hoc test program: capture the makefile's own lines once —
  `touch src/<any>.cpp; make -n | grep -- '-c src/<any>.cpp'` and
  `make -n | grep -- '-o FC43_x86_64/bin/' | head -1` — then reuse the
  compile line (minus `-c/-o`) and the link line's `-Wl,-rpath` list +
  `FC43_x86_64/lib64/libossl.a` + the lib tail. Run with
  `LD_LIBRARY_PATH` covering each sibling's `lib64`.
- `ossl_server -o 8101 -t -c <RDMFieldDictionary dir>` runs with omm's
  in-process test sources — no ADS or upstream needed for a smoke test.

## Versioning and release

- Version is `major_num.minor_num.patch_num-build_num` in `.copr/Makefile`
  (included by the GNUmakefile). `make spec_version` prints the
  `ossl_dep := MAJOR.MINOR` line dependents pin in `build_depends.mak`.
- `rpm/ossl.spec` carries placeholders (`Version: 999.999`, release
  `99999`, `BuildRequires: <dep> _<dep>_dep`); `make srpm` substitutes them
  from `build_depends.mak`. Keep the `_ensure_git` line in
  `.copr/Makefile`: COPR's `make_srpm` chroot has no git and every
  `$(shell git …)` would silently expand empty. A missing `<dep>_dep`
  entry fails the COPR build at install time, not link time.
- COPR: `injinj/dev` builds the `dev` branch of github.com/injinj/ossl
  on push (webhook); `injinj/rel` builds github.com/raitechnology/ossl.
  Remotes: `origin` = raitechnology (release), `ii` = injinj (dev).
  Chroots: epel-7/8/9/10, fedora-43/44/45/rawhide, x86_64.
- ABI convention: a dependent's `Requires` is `MAJOR.MINOR`, its
  `BuildRequires` the full version, and MINOR is bumped with any change to
  the C++ ABI of a public header, so a rebuilt dependent never silently
  loads an old `.so`. Bump `minor_num` here when public headers change,
  then re-pin and rebuild dependents.
- Link only against installable sibling libraries (`$(lnk_lib)`), never a
  sibling's object files; if a binary needs a sibling helper, move it into
  the sibling's library and release the sibling first.
- Signed rpms are published to https://www.raitechnology.com/repo/
  (COPR rel → download → sign → createrepo → rsync; tooling in `~/injinj/rel`).

## Code conventions

- C++11, two-space indent, `/* … */` block comments, aligned member
  comments; snake_case functions/variables, CamelCase types. System headers
  first, then project headers.
- Errors are return codes / status enums; no exceptions, no RTTI in library
  code. Raw pointers and placement-new over the repo's allocators are the
  norm; copy how neighbouring code allocates.
- Keep the generated `CMakeLists.txt` out of your edits — it is derived
  from the GNUmakefile (and slated for removal).

## Layout

- `docs/PROTOCOL.md` — connect record, frame, full header (SSL 4.0 / 4.5),
  compact 4.0 BE messages, element dictionaries, message sequences
  (mount, directory, open, image, update, group status, pings). The
  element names are the ones the SSL library's own tracer prints.
- `include/ossl/ipc.h`, `src/ipc.cpp` — frame/message parse and build,
  element tables, message type names.
- `src/` (4 files): server (sink distributor: mount → subscribe upstream
  via `EvOmmClient` + raikv route table → re-encode RWF field lists as
  Marketfeed), client.
- Usage:
  ```
  ossl_server -o 8101 -p ads1.www:14002 -c /path/to/RDMFieldDictionary_dir
  ossl_server -o 8101 -t -c /path/to/RDMFieldDictionary_dir     # test sources
  ossl_client -d ads1.www -c /path/to/RDMFieldDictionary_dir ADH1.INTC.O
  ```

## Contracts and gotchas

- Three dialects must stay supported: SSL 4.0, SSL 4.5 and 4.0 "BE"
  compact. Tested against the RFA 7.5 SSLED adapter (BE), the SSL 4.5
  demo (`-E ssl40`, `ssl45`, `sslauto`) and `ossl_client`, fed from ADS
  3.x and `omm_server`. Changing a header layout needs a re-test of all
  three.
- Marketfeed encoding is raimd's job: `MktfdMsg` decodes,
  `MktfdMsgWriter` encodes from an RWF field list through the field
  iterator with no intermediate model. Fix encoding bugs in raimd, not
  here.
- Upstream items arrive through omm's envelope contract
  (`EvPublish.hdr_len` delimits the RWF header); see omm/AGENTS.md.
- Version is `0.1.0`; the spec/COPR packaging follows the omm pattern
  (this was the first repo set up with the `deps.sh` / `build_depends.mak`
  flow in 2026-09).

## Tests

- `test/` is empty. Smoke: `ossl_server -t` + `ossl_client` against it.
  <!-- TODO: scripted smoke -->

## Open items / history

<!-- TODO: fill from git log -->
