# DHPKE

HPKE implementation for .NET with an F# core and a C# facade.

This repository provides two NuGet packages:

- `Dhpke.Hpke.CSharp`: recommended package for most .NET applications.
- `Dhpke.Hpke`: lower-level F# core APIs and primitives.

## Supported scope

Current implementation focuses on RFC 9180 style flows for:

- KEM: DHKEM(P-256, HKDF-SHA256)
- KDF: HKDF-SHA256
- AEAD: AES-128-GCM
- Modes: Base, PSK, Auth, AuthPSK

The codebase also includes strategy/delegate extension points for custom integration scenarios.

## Install

For C# or general .NET usage:

```bash
dotnet add package Dhpke.Hpke.CSharp
```

For direct F# core usage:

```bash
dotnet add package Dhpke.Hpke
```

## Quick start (C# facade)

```csharp
using System.Text;
using Hpke.CSharp;

var suite = HpkeSuite.DhKemP256_HkdfSha256_AesGcm128;
var recipient = HpkeKeyPair.Generate();

var plaintext = Encoding.UTF8.GetBytes("hello hpke");

var sender = HpkeSenderContext.Setup(suite, recipient.PublicKey);
var sealedValue = sender.Seal(plaintext);

var recipientContext = HpkeRecipientContext.Setup(
	suite,
	recipient.PrivateKey,
	sealedValue.EncappedKey);

var opened = recipientContext.Open(sealedValue.Ciphertext);
```

## Mode helpers (C# facade)

Use explicit helpers to avoid ambiguity:

- Base: `HpkeSenderContext.Setup(...)` / `HpkeRecipientContext.Setup(...)`
- PSK: `HpkeSenderContext.SetupPsk(...)` / `HpkeRecipientContext.SetupPsk(...)`
- Auth: `HpkeSenderContext.SetupAuth(...)` / `HpkeRecipientContext.SetupAuth(...)`
- AuthPSK: `HpkeSenderContext.SetupAuthPsk(...)` / `HpkeRecipientContext.SetupAuthPsk(...)`

## Custom delegation (HpkeStrategies)

`HpkeStrategies` lets you plug custom KEM/KDF/AEAD delegate implementations for advanced integration and testing.

```csharp
var strategies = new HpkeStrategies
{
	KemEncapsulate = recipientPublicKey =>
	{
		var (esk, epk) = Hpke.Core.Crypto.generateEcdhP256KeyPair();
		var shared = Hpke.Core.Crypto.deriveSharedSecret(esk, recipientPublicKey);
		return (epk, shared);
	},
	KemDecapsulate = (recipientPrivateKey, encappedKey) =>
		Hpke.Core.Crypto.deriveSharedSecret(recipientPrivateKey, encappedKey),
	KdfExtract = (salt, ikm) => Hpke.Core.Crypto.hkdfExtract(salt, ikm),
	KdfExpand = (prk, info, length) => Hpke.Core.Crypto.hkdfExpand(prk, info, length),
	AeadEncrypt = (key, nonce, aad, pt) => Hpke.Core.Crypto.aesGcmEncrypt(key, nonce, aad, pt),
	AeadDecrypt = (key, nonce, aad, ct) =>
	{
		var maybe = Hpke.Core.Crypto.aesGcmDecrypt(key, nonce, aad, ct);
		return maybe == null ? null : maybe.Value;
	},
	KeySize = 16,
	NonceSize = 12,
	TagSize = 16
};
```

## Quick start (F# core)

```fsharp
open Hpke.Core

let kem = DhKemP256HkdfSha256
let kdf = HkdfSha256
let aead = Aes128Gcm
let suite = Suites.create kem kdf aead

let recipientSk, recipientPk = Crypto.generateEcdhP256KeyPair ()

let sealedValue =
	Hpke.Hpke.BaseSealWithAlgorithms kem kdf aead {
		Suite = suite
		RecipientPublicKey = recipientPk
		Info = [||]
		Aad = [||]
		Plaintext = [| 1uy; 2uy; 3uy |]
	}
```

## Test vectors and validation

- RFC 9180 reference fixtures are under `tests/Hpke.Tests/rfc9180_vectors.json`.
- Tests include strict exporter assertions and sequence checks for available vector fields.

Run tests:

```bash
dotnet test
```

## Repository layout

- `src/Hpke`: F# core implementation
- `src/Hpke.CSharp`: C# facade and public entry points
- `tests/Hpke.Tests`: F# tests and RFC vector validation
- `tests/Hpke.CSharp.Tests`: C# facade/delegation tests
- `samples/Hpke.Sample`: C# usage samples
- `samples/Hpke.Sample.FSharp`: F# usage samples
