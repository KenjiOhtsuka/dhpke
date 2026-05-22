Packaging & NuGet guidance
==========================

Recommendation
- Publish one package that contains the compiled F# library and the C# facade: this keeps usage simple for .NET consumers (single NuGet package). If you want to publish two packages (F# core + C# facade) you can, but be explicit about dependency ordering.

Project metadata
- Add package metadata to `src/Hpke/Hpke.fsproj` (or the project files you intend to pack). Minimal fields:

```xml
<PropertyGroup>
  <PackageId>Hpke</PackageId>
  <Version>0.1.0</Version>
  <Authors>YourName</Authors>
  <Description>HPKE implementation in F# with C#-friendly API</Description>
  <PackageLicenseExpression>MIT</PackageLicenseExpression>
  <RepositoryUrl>https://github.com/your/repo</RepositoryUrl>
  <GeneratePackageOnBuild>true</GeneratePackageOnBuild>
</PropertyGroup>
```

Build & pack

```powershell
dotnet pack src\Hpke\Hpke.fsproj -c Release
# Or pack the solution
dotnet pack Dhpke.slnx -c Release
```

Publishing

```powershell
dotnet nuget push bin\Release\Hpke.*.nupkg --api-key $API_KEY --source https://api.nuget.org/v3/index.json
```

Target frameworks
- Recommend targeting `net8.0` for the package (highest LTS for broad compatibility). The code in the workspace currently builds for `net10.0`; if you publish for `net8.0` also, include `TargetFrameworks` or multi-target.

CI notes
- Add a GitHub Actions workflow that builds, tests, and packs on push to main and publishes on tags. Use `dotnet/shell` actions and `NuGet/setup-nuget` or `dotnet nuget push` with secrets.

Security
- Do not include test fixtures, private keys, or vector files in the published package. Keep those in the repo only.
