########################################
# IPinfo.io API Tool
# https://github.com/wakefieldite/automation/ipinfo.ps1
########################################
#Dependencies
# Install-Module Microsoft.PowerShell.SecretManagement
# Install-Module Microsoft.PowerShell.SecretStore
# Note: Do not use SecureString. See https://github.com/dotnet/platform-compat/blob/master/docs/DE0001.md
# For information on managing secretstore see https://learn.microsoft.com/en-us/powershell/utility-modules/secretmanagement/how-to/manage-secretstore?view=ps-modules
########################################

# Variable configuration
$dependencies = @('Microsoft.PowerShell.SecretManagement','Microsoft.PowerShell.SecretStore')
$secrettoken = "ipinfo-api-token"

#Dependency Check, installs modules and imports, otherwise imports the dependencies.
Foreach ($dependency in $dependencies){
    if (Get-Module -ListAvailable -Name $dependency ) {
        Write-Host "Dependency Check:" $dependency "module exists"
        Import-Module $dependency
    }
    else {
        Write-Host "Dependency Check:" $dependency "does not exist."
        Install-Module $dependency
        Write-Host $dependency "module installed"
        Import-Module $dependency
    }
}

# Check to see if there is a Vault, create a vault if no vault exists.
$secretvault = Get-SecretVault
if ($null -eq $SecretVault){
    Write-Host 'No vault found. Creating vault.'
    Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
    } else { 
    Write-Host 'Vault found.'
    }

# Check to see if Vault entry exists for IPinfo.io
# The first time you access the vault you must provide a password for the new vault.
# This password is used to lock and unlock the vault.
Write-Host "Checking for Secret:" $secrettoken". Password prompt is expected."
$getsecret = Get-Secret -Name $secrettoken
if ($null -eq $getsecret){
    Write-Host $secrettoken "- Secret not found."
    Write-host 'Enter the API token in the next prompt.'
    Set-Secret -NoClobber -Name $secrettoken 
} else {
    Write-Host $secrettoken "- Secret found."
}

# Define the input and output file paths
$inputFile = Read-Host 'Please enter the absolute path of your IP list'
if (!$inputfile){
    $inputFile = "./input.txt"
}
$outputFile = Read-Host 'Please enter the absolute path for where output.csv is to be written, including the file and extension'
if (!$outputFile){
    $outputFile = "./output.csv"
}

# Set Invoke-RestMethod Parameters
$Params = @{
    Method = "GET"
    Authentication = 'Bearer'
    Token = $getsecret
    Content='application/json'
}

# Read the IP addresses from the input file
$ips = Get-Content -Path $inputFile

# Clear content in output file
Clear-Content $outputFile

# Create First line of CSV with headers
Add-Content -Path $outputFile -Value 'ip,hostname,city,region,country,loc,org,postal,timezone'

# Loop through each IP address
foreach ($ip in $ips) {
    # Trim any whitespace from the IP address
    $ip = $ip.Trim()
    $url = "https://ipinfo.io/"+$ip+"/json"

    # Check if the IP address is valid
    if ([System.Net.IPAddress]::TryParse($ip, [ref]$null)) {
        # Fetch the data from the API
        $response = Invoke-RestMethod -uri $url @Params

        # Debugging: Print the response to the console
        Write-Output "Response for IP $ip $response"

        # Check response to see if valid data is returned
        if ($response -match 'country') {
            # Debugging: Print the extracted value to the console
            Write-Output "Extracted Data: $response"

            # Append the result to the output file
            Add-Content -Path $outputFile -Value $($response | ConvertTo-Csv | Select-Object -Index 1)
        } else {
            # Debugging: Print a message if the regex did not match
            Write-Output "No match found for IP $ip"
            
            Add-Content -Path $outputFile -Value 'null'
        }
    } else {
        Write-Output "Invalid IP address: $ip"
    }
}
