param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('chrome', 'edge', 'firefox')]
  [string]$Target
)

$extensionRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$distRoot = Join-Path $extensionRoot 'dist'
$source = Join-Path $distRoot $Target
if (-not (Test-Path -LiteralPath $source -PathType Container)) {
  throw "Build the $Target extension first with scripts/build.mjs."
}

$resolvedSource = (Resolve-Path -LiteralPath $source).Path
$resolvedDist = [IO.Path]::GetFullPath($distRoot) + [IO.Path]::DirectorySeparatorChar
if (-not $resolvedSource.StartsWith($resolvedDist, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Refusing to package a directory outside the extension dist folder."
}

$archive = Join-Path $distRoot "DLP-Guard-$Target.zip"
if (Test-Path -LiteralPath $archive -PathType Leaf) {
  Remove-Item -LiteralPath $archive -Force
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory(
  $resolvedSource,
  $archive,
  [IO.Compression.CompressionLevel]::Optimal,
  $false
)
Get-FileHash -LiteralPath $archive -Algorithm SHA256 | Select-Object Algorithm, Hash, Path
