[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
& node (Join-Path $PSScriptRoot '..\build-custom-agents.mjs')
if ($LASTEXITCODE -ne 0) {
    throw "Custom Agents generation failed with exit code $LASTEXITCODE."
}
