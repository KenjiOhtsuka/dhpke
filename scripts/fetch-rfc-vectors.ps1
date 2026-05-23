$uri = 'https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json'
$out = Join-Path -Path (Resolve-Path -Path .).Path -ChildPath 'tests\Hpke.Tests\rfc9180_vectors.json'
Write-Host "Downloading $uri -> $out"
try {
    Invoke-WebRequest -Uri $uri -OutFile $out -ErrorAction Stop
    Write-Host "Saved to $out"
    exit 0
} catch {
    $err = $_.Exception.Message
    Write-Error ("Failed to download {0}: {1}" -f $uri, $err)
    exit 1
}