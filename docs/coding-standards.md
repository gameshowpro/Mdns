# Coding standards

Follow the shared [GameshowPro coding standards](../../Docs/docs/coding-standards.md). This repository uses Soundling's analyzer policy, with the following explicit choices:

- Use **C# 14**, as requested for this work. C# 15 examples in the shared document do not apply. Preserve constructor arguments such as collection comparers using constructors where C# 14 collection expressions cannot express them.
- `global.json` pins the same SDK as Soundling. The library still targets .NET 10 and .NET 10 Windows for existing consumers.
- `Directory.Build.props` enables nullable analysis, recommended .NET analyzers, build-time style checks, Roslynator, and warnings as errors for production and test projects. XML documentation is generated for analyzer coverage; missing public XML comments are exempt, matching Soundling.
- `.editorconfig` carries the shared naming and style rules, including explicit types, braces, target-typed construction, and explicit discards. Imports belong in each project's `GlobalUsings.cs`.
- `Directory.Build.targets` rejects Newtonsoft.Json dependencies. Production code uses GameshowPro.Common's JSON support; `BannedSymbols.txt` enforces that boundary. Analyzer packages are private build dependencies.
- Preserve existing public method names, including `Async` suffixes, to retain consumer compatibility. New private helpers follow the shared naming convention. Interface methods retain their required names.
- Keep suppressions local and explain the actual reason. Do not weaken repository-wide severities to make a build pass. Mutable protocol buffers and locked transport state may retain mutable collections where copying would change performance or ownership semantics.

Run both configurations before shipping:

```powershell
dotnet test tests/GameshowPro.Mdns.Tests/GameshowPro.Mdns.Tests.csproj -c Release
dotnet test tests/GameshowPro.Mdns.Tests/GameshowPro.Mdns.Tests.csproj -c ReleaseWindows
```

CI uses the pinned SDK and enforces warnings as errors for tests and packaging. Apply automated fixes selectively and review their effect on protocol behavior; follow the shared document's warnings about unsafe fixers.
