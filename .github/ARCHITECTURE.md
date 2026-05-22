Repository architecture and developer guidance
===========================================

This document describes the current project layout, design decisions, and where to change behavior.

Projects
- src/Hpke — F# library (core protocol flows, types, strategy hooks).
- src/Hpke.CSharp — C# facade that exposes context-style APIs and convenience helpers. This project also contains `HpkeStrategies` (delegate-based) to inject custom algorithms from C#.
- tests/Hpke.Tests — F# test project with RFC 9180 vectors and round-trip tests.
- samples/Hpke.Sample — C# sample app demonstrating the public C# API (context-style one-shot and context flows).
- samples/Hpke.Sample.FSharp — F# sample showing direct use of the F# core and custom strategies.

Key code locations
- `src/Hpke/Core/Crypto.fs` — low-level primitives (ECDH P-256, HKDF, AES-GCM). Keep crypto primitives here.
- `src/Hpke/Core/Types.fs` — core types including F# `HpkeStrategies` record for algorithm injection.
- `src/Hpke/Library.fs` — protocol flows; strategy-aware functions such as `BaseSealWithStrategies` and `BaseOpenWithStrategies`.
- `src/Hpke.CSharp/HpkeApi.cs` — C# public API, delegates, config factories, and sample helpers.

Design highlights
- F# core: Use discriminated unions and small immutable types to represent suites, modes, and contexts. Keep the heavy protocol logic in F# for safety and concision.
- C# facade: Provide ergonomic C# classes and methods (Sender/Recipient contexts, static Setup helpers). Where C# consumers want custom algorithms, they can pass a `HpkeStrategies` instance with delegates.
- Extensibility: `HpkeStrategies` is the injection point for custom KEM/KDF/AEAD. The F# library will prefer provided strategies and fall back to the built-in `Crypto` implementations.

Development flow
1. Build: `dotnet build Dhpke.slnx`
2. Run tests: `dotnet test tests\\Hpke.Tests\\Hpke.Tests.fsproj --no-build`
3. Run C# sample: `dotnet run --project samples\\Hpke.Sample\\Hpke.Sample.csproj`

Notes and cautions
- F# `option` types map to `Microsoft.FSharp.Core.FSharpOption<T>` in C# — handle those explicitly (see how `Crypto.aesGcmDecrypt` returns `byte[] option` and how the C# facade converts it to `byte[]?`).
- When adding new algorithms or changing KDF/AEAD sizes, update both F# `HpkeStrategies` defaults and the C# `HpkeStrategies` wrappers.

If you need a single-file version of the original, or a translated Japanese copy, I can generate them.
