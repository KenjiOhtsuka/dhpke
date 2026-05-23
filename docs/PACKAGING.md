Packaging and Multi-targeting

This repository contains an F# core library (`src/Hpke`) and a C# facade (`src/Hpke.CSharp`).

Goals in packaging:
- Produce NuGet packages for the F# core and C# facade.
- Keep defaults conservative: `GeneratePackageOnBuild` is disabled. Use `dotnet pack` to create packages.

Quick pack commands:

```bash
dotnet pack src/Hpke/Hpke.fsproj -c Release -o ./nupkgs
dotnet pack src/Hpke.CSharp/Hpke.CSharp.csproj -c Release -o ./nupkgs
```

Multi-targeting guidance

The projects currently target `net10.0`. If you want to multi-target (for example to support `net6.0` and `net10.0`), update the project `PropertyGroup` to use `TargetFrameworks`:

```xml
<PropertyGroup>
  <TargetFrameworks>net6.0;net10.0</TargetFrameworks>
  <GenerateDocumentationFile>true</GenerateDocumentationFile>
</PropertyGroup>
```

Notes and caveats:
- Multi-targeting may require conditional code if APIs differ across frameworks (e.g. `AesGcm` constructors). Prefer to test builds for each target.
- Update CI to run `dotnet build -f <TFM>` for each target framework.

Package metadata

The core and facade projects include basic `PackageId`, `Version`, `Authors`, `Description`, and `RepositoryUrl` fields. Update `RepositoryUrl` and `Version` before publishing.

CI suggestion

Create a GitHub Actions workflow that restores, builds, runs tests, and optionally packs on tags. Example steps:
- `dotnet restore` then `dotnet build --no-restore -c Release`
- `dotnet test --no-build -c Release`
- `dotnet pack -c Release -o ./nupkgs` (on release tag)

If you want, I can scaffold a `.github/workflows/ci.yml` that builds, tests, and packs on tags.