
function Log {
    param (
        [string] $msg
    )
    Write-Host "---------------------------------------------" -ForegroundColor Green
    Write-Host $msg -ForegroundColor Green
    Write-Host "---------------------------------------------" -ForegroundColor Green
}

Log "Creating snapshot directory"
$date = Get-Date -Format "MM.dd.yyyy"

$exportDirectory = "$env:COMPUTERNAME-snapshot-$date"

New-Item -Path .\$exportDirectory -ItemType Directory

Log "Getting a list of all services on the machine"
Get-Service | Select-Object -Property Name, DisplayName, Status | Export-Csv .\$exportDirectory\services.csv

Log "Getting a list of all installed programs from the registry"
$InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
$software = @()

foreach($obj in $InstalledSoftware)
{
    $newObj = New-Object PSObject
    $newObj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $obj.GetValue('DisplayName')
    $newObj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $obj.GetValue('DisplayVersion')
    $newObj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $obj.GetValue('Publisher')
    
    $software += $newObj;
}

$software | Sort-Object -Property DisplayName | Export-Csv .\$exportDirectory\installed-programs.csv

Log "Dumping disk drive information"
Get-Disk | Format-List -Property * | Out-File .\$exportDirectory\disk-information.txt

Log "Getting drive information"
Get-PSDrive | Format-List -Property * | Out-File .\$exportDirectory\drive-information.txt

Log "Getting user accounts"
Get-LocalUser | Select-Object * | Out-File .\$exportDirectory\local-users.txt

Log "Getting local groups" 
Get-LocalGroup | Select-Object * | Out-File .\$exportDirectory\local-groups.txt

Log "Getting local group memberships"
$grps = Get-LocalGroup 

Log "Creating folder for group memberships"

New-Item -Path .\$exportDirectory\group-memberships -ItemType Directory

foreach($obj in $grps.Name)
{
    Log "Getting group membership for: $obj"
    Get-LocalGroupMember -Group $obj | Out-File .\$exportDirectory\group-memberships\$obj-group-membership.txt
}

Log "Creating log exports"

Log "Creating directory for logs"

New-Item -Path .\$exportDirectory\log-export -ItemType Directory

Log "Exporting the Application logs"
Get-EventLog -LogName Application | Export-Csv .\$exportDirectory\log-export\application.csv

Log "Exporting the System logs"
Get-EventLog -LogName System | Export-Clixml .\$exportDirectory\log-export\System.csv

# Get the security log 
#  This script must be running as an administrator in order to pull this data down
#Get-EventLog -LogName Security | Export-Csv .\$exportDirectory\log-export\security.csv

Log "Compressing archive"
Compress-Archive -Path .\$exportDirectory -DestinationPath .\$exportDirectory.zip

Remove-Item .\$exportDirectory -Recurse