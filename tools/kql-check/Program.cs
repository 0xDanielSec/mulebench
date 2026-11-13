// Parse and analyze every *.kql file in a directory against the
// MulebenchTrace_CL schema; print errors and exit 1 if any.
//
// Usage: dotnet run --project tools/kql-check -- <dir> "<schema>"
//   <schema> is "(TimeGenerated:datetime, EventType:string, ...)".
using Kusto.Language;
using Kusto.Language.Symbols;

if (args.Length != 2)
{
    Console.Error.WriteLine("usage: kql-check <dir> \"(col:type, ...)\"");
    return 2;
}

var table = new TableSymbol("MulebenchTrace_CL", args[1]);
var globals = GlobalState.Default.WithDatabase(new DatabaseSymbol("Mulebench", table));
var failed = 0;
foreach (var path in Directory.GetFiles(args[0], "*.kql").OrderBy(p => p))
{
    var code = KustoCode.ParseAndAnalyze(File.ReadAllText(path), globals);
    var errors = code.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
    foreach (var e in errors)
    {
        Console.WriteLine($"{Path.GetFileName(path)}:{e.Start}: {e.Code} {e.Message}");
    }
    if (errors.Count > 0)
    {
        failed++;
    }
}
Console.WriteLine(failed == 0 ? "ok" : $"{failed} file(s) with errors");
return failed == 0 ? 0 : 1;
