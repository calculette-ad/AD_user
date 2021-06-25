Import-Module ActiveDirectory
#Import-Module NTFSSecurity
$Users = Import-Csv -Delimiter ";" -Path "C:\Tools\AD_user\userlist.csv"
foreach ($User in $Users)  
{  
    $OU = "OU=E2C-Utilisateurs,DC=e2c,DC=local"
    $Password = $User.password 
    $Detailedname = $User.firstname + " " + $User.name 
    $UserFirstname = $User.Firstname 
    $FirstLetterFirstname = $UserFirstname.substring(0,1) 
    $SAM = $FirstLetterFirstname + $User.name
   # $Profilepath = $User.Profilpath + $SAM
    $homeDirectory = $User.homeDirectory + $SAM
    $homeDrive = $User.homeDrive
    #$FolderProfile = "C:\profiles\"
    $HomeFolder = "\\E2CSERVEUR3\Stagiaires\P10\"
    $AclPath = "\\E2CSERVEUR3\Stagiaires\P10\" + $Detailedname
    $AclPathProfiles = $FolderProfile + $Detailedname
    $Account = "e2c\" + $SAM
New-ADUser -Name $Detailedname -SamAccountName $SAM -UserPrincipalName $SAM -DisplayName $Detailedname -GivenName $user.firstname -Surname $user.name -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) -homeDirectory $homeDirectory -homeDrive $homeDrive -Enabled $true -Path $OU -ChangePasswordAtLogon $false -PasswordNeverExpires $true
If (-not (Test-Path "$HomeFolder + $Detailedname")) { New-Item -ItemType Directory -Name $Detailedname -Path $HomeFolder} else {Write-Output "Le fichier $Detailedname existe deja!"}
#If (-not (Test-Path "$FolderProfile + $SAM")) { New-Item -ItemType Directory -Name $SAM -Path $FolderProfile} else {Write-Output "Le fichier $SAM existe deja!"}
#Add-NTFSAccess -Path $AclPath -Account $Account -AccessRights FullControl
#Add-NTFSAccess -Path $AclPathProfiles -Account $Account -AccessRights FullControl

}

<#$properties = “HomeFolder”,”ScriptPath”, “l”
Get-ADUser -Filter * -SearchBase $OU -Properties $properties |
ForEach-Object {

 $HomeFolder = “\\E2CSERVEUR3\Stagiaires\P90\{1}” -f $_.l, $_.SamAccountName
 $ScriptPath = “netmaplogon.cmd” -f $_.l
 Set-ADUser $_.samaccountname -ProfilePath $HomeFolder -ScriptPath $ScriptPath
}#>