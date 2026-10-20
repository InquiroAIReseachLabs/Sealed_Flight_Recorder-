# Notice: third-party material

This repository includes or quotes the third-party material below. Everything else is covered by the Rights section of `README.md`.

## PX4

`docs/RULES.md`, `examples/rules.default.toml` and `examples/rules.extended.toml` quote short excerpts of the PX4-Autopilot source (message field names and types, command ids from `VehicleCommand.msg`, enum values, lines of the startup script `rcS`), each cited by file and line. The golden logs in `testdata/sitl/` were recorded from unmodified PX4 in simulation; each log's `.provenance.md` gives the version and commit. PX4 is under the BSD 3-Clause License, as the `LICENSE` file in the PX4-Autopilot repository states:

```text
BSD 3-Clause License

Copyright (c) 2012 - 2025, PX4 Development Team
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## pyulog sample log

`testdata/pyulog/sample.ulg` is the sample log of the PX4 pyulog project, copied unmodified (`testdata/pyulog/NOTICE.md` gives the source and commit). It is under the BSD 3-Clause License, Copyright (c) 2016, PX4 Pro Drone Autopilot; the full text is in `testdata/pyulog/LICENSE.md`. The fuzz seeds cut from it (`fuzz/seeds/ulog_ingest/pyulog_sample_first_65516.ulg` and the record sealed from that cut in `fuzz/seeds/sfr_verify/`) have the same license.

## Direct dependencies

The crates `sfr` depends on directly, with the licenses `cargo deny --all-features list` reports (`Cargo.lock` pins the versions; `deny.toml` lists the licenses allowed). Each crate's source carries its license text, and the SBOM of each build lists every crate in the graph with its license.

| Crate | Version | License |
|---|---|---|
| `blake3` | 1.8.7 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |
| `ed25519-dalek` | 3.0.0 | BSD-3-Clause |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 |
| `sha2` | 0.11.1 | MIT OR Apache-2.0 |
| `toml` | 0.9.12 | MIT OR Apache-2.0 |
| `zeroize` | 1.9.1 | Apache-2.0 OR MIT |
