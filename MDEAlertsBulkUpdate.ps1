#Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All","SecurityActions.ReadWrite.All","SecurityEvents.ReadWrite.All"


#   Filter on Category (Execution, InitialAccess, Persistence, Collection, Malware, CredentialAccess, SuspiciousActivity, 
#   Discovery, LateralMovement, None, Reconnaissance, ResourceDevelopment,  PrivilegeEscalation, DefenseEvasion, 
#   UnfamiliarLocation, ThreatManagement, CommandandControl, Exfiltration, Impact.
#$alertid = Get-MgSecurityAlert | where-object {$_.Category -EQ 'Execution'} 

#   Filter on AssignedTo
$alertid = Get-MgSecurityAlert | where-object {$_.AssignedTo -eq 'Automation'}

#   Filter on FileStates to look for specific files such as PowerShell scripts
#$alertid = Get-MgSecurityAlert | where-object {$_.FileStates -contains 'test.ps1' -or 'test.zip'}

#   Filter on Alert Title
#$alertid = Get-MgSecurityAlert | where-object {$_.Title -contains 'Suspicious service launched'}

#   Filter on Severity (low, meduim, high, informational)
#$alertid = Get-MgSecurityAlert | where-object {$_.Severity -eq 'medium'}

#   Filter on AlertID
#$alertid = Get-MgSecurityAlert | where-object {$_.Id -eq 'xxxxxxxx134609903_-1317628283'}

#alert status options: newAlert, resolved


$params = @{
	Comments = @(
		"YOUR COMMENT"
	)
	Status = "resolved"
	VendorInformation = @{
		Provider = "Microsoft Defender ATP"
		ProviderVersion = $null
		SubProvider = "MicrosoftDefenderATP"
		Vendor = "Microsoft"
	}
}

foreach ($alert in $alertid)
{
$alert.id | Out-String 
Update-MgSecurityAlert -AlertId ($alert).ID -BodyParameter $params
}
