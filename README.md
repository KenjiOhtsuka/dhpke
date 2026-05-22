# Dhpke

HPKE implementation for .NET with an F# core and a thin public surface.

## What is included

- `src/Hpke`: core HPKE implementation and helpers
- `tests/Hpke.Tests`: xUnit tests for the supported modes
- `tests/Hpke.Tests/rfc9180_vectors.json`: RFC 9180 Appendix A.3 reference fixtures for the supported P-256 / HKDF-SHA256 / AES-128-GCM suite
- `samples/Hpke.Sample`: C# sample app
- `samples/Hpke.Sample.FSharp`: F# sample app

## Current scope

The codebase currently focuses on the P-256 / HKDF-SHA256 / AES-128-GCM suite and includes mode coverage for Base, PSK, Auth, and AuthPSK.

The core types keep extension points for additional KEM, KDF, and AEAD identifiers, and the runtime now validates the supported suite explicitly.

## Run tests

```powershell
dotnet test tests/Hpke.Tests/Hpke.Tests.fsproj
```

## Notes

- `rfc9180_vectors.json` is included as a reference fixture set.
- The repository is structured to make it easier to extend additional suites later.
- Both sample apps demonstrate sealing and opening for all four modes.
