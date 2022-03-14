Param ($Source, $Target, $StartDate)

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Sleep 1
    Write-Host "                                               2"
    Start-Sleep 1
    Write-Host "                                               1"
    Start-Sleep 1
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

If ($Source -ne $Null -and $Target -eq $Null)
{
    $Target = Read-Host "Enter logon name of target user"
}
If ($Source -eq $Null)
{
    $Source = Read-Host "Enter logon name of Source User (User you would like to base permissons off): "
    $Target = Read-Host "Enter logon name of Target User (User you would like to replicate permissions to): "
    $StartDate = Read-Host "Enter Start Date of user (E.G Monday21, Monday07): "

}

Write-Host("")

# Retrieve group memberships.
$SourceUser = Get-ADUser $Source -Properties memberOf, scriptpath, manager, Organization, Department, Company
$TargetUser = Get-ADUser $Target -Properties memberOf

# Set Password to Secure String
$StartDateAsPassword = ConvertTo-SecureString $StartDate -AsPlainText -Force

$Script = $SourceUser.scriptpath

# Hash table of source user groups.
$List = @{}

# Enumerate direct group memberships of source user.
ForEach ($SourceDN In $SourceUser.memberOf)
{
    # Add this group to hash table.
    $List.Add($SourceDN, $True)
    # Bind to group object.
    $SourceGroup = [ADSI]"LDAP://$SourceDN"

    # Check if target user is already a member of this group.
    If ($SourceGroup.IsMember("LDAP://" + $TargetUser.distinguishedName) -eq $False)
    {
        # Duplicates permissions from the Source user to the target user, and sets the following AD Fields: Login Script, Manager, Company, Organization, Department and Email address.
        
        Try { Add-ADGroupMember $SourceDN -Members $Target }
            catch [Microsoft.ActiveDirectory.Management.ADException],[Microsoft.ActiveDirectory.Management.Commands.AddADGroupMember]{ 
            Write-Host ("You do not have permissions to add user to group:", $SourceDN)
            Write-Host ("")
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{ 
            Write-Host ("The Specified Group does not exist in your specific domain:", $SourceDN) 
            Write-Host ("")
            } 
        if (!$error) { 
        Write-Host ("Added Group:",$SourceDN)
        Write-Host ("") }
            else { $error.clear() }

     }
}

# The below lines ensure that the user account is not locked out, and is enabled. 
    Enable-ADAccount -Identity $Target
    Unlock-ADAccount -Identity $Target

    Write-Host ("Unlocked and Enabled user account:", $Target)
    Write-Host ("")

# Set user's password to Start Date user entered.

    Set-ADAccountPassword -Identity $Target -NewPassword $StartDateAsPassword

    Write-Host ("Set user's password to: ", $StartDate)
    Write-Host ("")

#Set Script same as user who we are basing permissions off.

    Set-ADUser $Target -ScriptPath $Script

    if ($script -eq '') { Write-Host ("No logon script to set.") }
    else { Write-Host ("Set User's logon script to:", $Script) }
    Write-Host ("")
    pause

    

