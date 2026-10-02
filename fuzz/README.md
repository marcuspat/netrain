# Fuzzing

Two layers:

1. **`tests/fuzz_smoke.rs`** - a deterministic mutation fuzzer that runs on stable Rust with
   `cargo test`. It mutates valid packets and capture files and drives every parser plus the
   stateful pipeline (capture channel, UI state, analyser, JSON exporter). Raise the iteration
   count for a longer run; use a debug build so arithmetic overflow is checked:

   ```sh
   NETRAIN_FUZZ_ITERS=2000000 cargo test --test fuzz_smoke
   ```

2. **`fuzz/`** - coverage-guided targets for `cargo-fuzz` (nightly only):

   ```sh
   cargo install cargo-fuzz
   cargo +nightly fuzz run decode
   cargo +nightly fuzz run inspect
   cargo +nightly fuzz run pcap_file -- -max_len=4096
   ```

   Seed the corpus with `tests/fixtures/*.pcap` for `pcap_file`.

The `cargo-fuzz` targets were written alongside the stable fuzzer but have not been run: the
environment they were written in had no nightly toolchain.
