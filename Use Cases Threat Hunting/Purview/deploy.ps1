[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $SubscriptionId,
    [Parameter(Mandatory = $true)] [string] $ResourceGroup,
    [Parameter(Mandatory = $false)][string] $TemplateFile      = "$PSScriptRoot\azuredeploy.json",
    [Parameter(Mandatory = $false)][string] $ParametersFile    = "$PSScriptRoot\azuredeploy.parameters.json",
    [Parameter(Mandatory = $false)][string] $DeploymentName    = "purview-sentinel-pack-$(Get-Date -Format yyyyMMddHHmmss)",
    [Parameter(Mandatory = $false)][switch] $WhatIf
)

$ErrorActionPreference = 'Stop'

Write-Host "Setting subscription $SubscriptionId" -ForegroundColor Cyan
az account set --subscription $SubscriptionId | Out-Null

if ($WhatIf) {
    Write-Host "Running what-if for $DeploymentName in $ResourceGroup" -ForegroundColor Yellow
    az deployment group what-if `
        --resource-group $ResourceGroup `
        --name $DeploymentName `
        --template-file $TemplateFile `
        --parameters "@$ParametersFile"
    return
}

Write-Host "Deploying $DeploymentName to $ResourceGroup" -ForegroundColor Cyan
az deployment group create `
    --resource-group $ResourceGroup `
    --name $DeploymentName `
    --template-file $TemplateFile `
    --parameters "@$ParametersFile" `
    --output table
