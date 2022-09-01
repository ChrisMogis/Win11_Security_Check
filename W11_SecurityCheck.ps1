################################################################################################
# This script can be used to execute security check on Windows 10 & 11                         #
# Editor : Christopher Mogis                                                                   #
# Date : 08/31/2022                                                                            #
# Version 1.1                                                                                  #
# - Add Bitlocker Encryption Method                                                            #
################################################################################################

#Variables
$Date = Get-Date
$Computer = (Get-CimInstance -ClassName Win32_ComputerSystem).Name

#Computer Informations
    Write-Host ""
    Write-Host "#### Computer Informations ####"
    Write-Host "$Date - $Computer - Security Audit "
    Write-Host ""

#Check all security components
    Write-Host "#### Check Windows Defender ####"
    $Defender = (Get-MpComputerStatus).RealTimeProtectionEnabled
        if ($Defender -eq "True")
        {
            Write-Host "Windows Defender is enabled" -ForegroundColor Green <# Action to perform if the condition is true #>
        }
        else 
        {
            Write-Host "WARNING - Windows Defender is not enabled" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
        }
    $DefenderDef = (Get-MpComputerStatus).AntivirusSignatureAge
    if ($DefenderDef -eq "0")
        {
            Write-Host "Windows Defender is up to date" -ForegroundColor Green <# Action to perform if the condition is true #>
        }
        else 
        {
            Write-Host "WARNING - Windows Defender is not up to date" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
        }
        Write-Host " > Last Quick Scan : " (Get-MpComputerStatus).FullScanEndTIme -ForegroundColor Yellow
        Write-Host " > Last Full Scan Scan : " (Get-MpComputerStatus).FullScanEndTIme -ForegroundColor Yellow

    Write-Host "" 
    Write-Host "#### Check Windows firewall ####"
    $FWLPublic = (Get-NetFirewallProfile -Profil public).Enabled
    $FWLDomain = (Get-NetFirewallProfile -Profil domain).Enabled
    $FWLPrivate = (Get-NetFirewallProfile -Profil Private).Enabled
        if ($FWLPublic -AND $FWLDomain -AND $FWLPrivate -eq "True") 
        {
            Write-Host "Your firewall configuration is OK" -ForegroundColor Green <# Action to perform if the condition is true #>
        }
        else 
        {
            Write-Host "WARNING - Windows firewall is not correctly configure" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
        }
            Write-Host " > Public zone : $FWLPublic" -ForegroundColor Yellow
            Write-Host " > Private zone : $FWLPrivate" -ForegroundColor Yellow
            Write-Host " > Domain zone : $FWLDomain" -ForegroundColor Yellow

    Write-Host ""
    Write-Host "#### Check Secure Boot ####"
    $SecureBoot = Confirm-SecureBootUEFI
        if ($SecureBoot -eq "True") 
        {
            Write-Host "Secure Boot is enabled" -ForegroundColor Green <# Action to perform if the condition is true #>
        }
        else 
        {
            Write-Host "Secure Boot is not enabled" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
        }

    Write-Host ""
    Write-Host "#### Check Bitlocker encryption ####"
    $Bitlocker = (Get-BitLockerVolume -MountPoint C:).ProtectionStatus
        if ($Bitlocker -eq "On") 
        {
            Write-Host "Your System volume is encrypted" -ForegroundColor Green <# Action to perform if the condition is true #>
        }
        else 
        {
            Write-Host "Your System volume is not encrypted" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
        }
            Write-Host " > Bitlocker Encryption Method : " (Get-BitLockerVolume -MountPoint C).EncryptionMethod -ForegroundColor Yellow

    Write-Host ""
    Write-Host "#### Check Windows Update ####"
    Get-Hotfix -Description "Security*" | Sort-Object InstalledOn

    Write-Host ""
    Write-Host "#### Check Windows Hypervisor Status ####"
    $HyperV = (Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online).State
    if($HyperV -eq "Enabled")
    {
        Write-Host "Windows Hypervisor is enabled on your computer" -ForegroundColor Green <# Action to perform if the condition is true #>
    }
    else 
    {
        Write-Host "INFO - Windows Hypervisor is not enabled on your computer" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
    }

    Write-Host ""
    Write-Host "#### Check Credential Guard status ####"
    $CredentialGuard = ((Get-ComputerInfo).DeviceGuardSecurityServicesRunning)
    if ($CredentialGuard -eq "CredentialGuard") 
    {
        Write-Host "Credential Guard is activated" -ForegroundColor Green <# Action to perform if the condition is true #>
    }
    else 
    {
        Write-Host "WARNING - Credential Guard is not activated" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
    }

    Write-Host ""
    Write-Host "#### Check Device Guard status ####"
    $DeviceGuard = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus
    if ($DeviceGuard -eq "2") 
    {
        Write-Host "Device Guard is activated" -ForegroundColor Green <# Action to perform if the condition is true #>
    }
    else 
    {
        Write-Host "WARNING - Device Guard is not activated" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
    }


    Write-Host ""
    Write-Host "#### Check App Guard status ####"
    $AppGuard = (Get-WindowsOptionalFeature -FeatureName "Windows-Defender-ApplicationGuard" -Online).State
    if ($AppGuard -eq "Enabled") 
    {
        Write-Host "App Guard is activated" -ForegroundColor Green <# Action to perform if the condition is true #>
    }
    else 
    {
        Write-Host "WARNING - App Guard is not activated" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
    }

    Write-Host ""
    Write-Host "#### Check SMB v1 status ####"
    $SMBv1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
    if ($SMBv1 -eq "Disabled") 
    {
        Write-Host "SMB v1 is not enabled on your Computer" -ForegroundColor Green <# Action to perform if the condition is true #>
    }
    else 
    {
        Write-Host "Critical - SMB v1 is enabled on your Computer" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
    }
    
    Write-Host ""
    Write-Host "#### Check TLS 1.2 status ####"
    $keyTLS12 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\'
    if (Test-Path $keyTLS12) 
    {
        $TLS12 = Get-ItemProperty $keyTLS12
        if ($TLS12.DisabledByDefault -ne 0 -or $TLS12.Enabled -eq 0) 
        {
            Write-Host "TLS 1.2 Not enabled" -ForegroundColor Red <# Action to perform if the condition is true #>
        }
        else 
        {
            Write-Host "TLS 1.2 enabled" -ForegroundColor Green <# Action when all if and elseif conditions are false #>
        }
    }

    Write-Host ""
    Write-Host "#### Check SSL 2.0 status ####"
    $KEYSSL20 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client\'
    if (Test-Path $KEYSSL20) 
    {
        $SSL20 = Get-ItemProperty $KEYSSL20
        if ($SSL20.DisabledByDefault -ne 0 -or $SSL20.Enabled -eq 0) 
        {
            Write-Host "SSL 2.0 not enabled" -ForegroundColor Green <# Action to perform if the condition is true #>
        }
        else 
        {
            Write-Host "SSL 2.0 enabled" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
        }
    }

    Write-Host ""
    Write-Host "#### Check SSL 3.0 status ####"
    $KEYSSL30 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\'
    if (Test-Path $KEYSSL30) 
    {
        $SSL30 = Get-ItemProperty $KEYSSL30
        if ($SSL30.DisabledByDefault -ne 0 -or $SSL30.Enabled -eq 0) 
        {
            Write-Host "SSL 3.0 not enabled" -ForegroundColor Green <# Action to perform if the condition is true #>
        }
        else 
        {
            Write-Host "SSL 3.0 enabled" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
        }
    }

    Write-Host ""
    Write-Host "#### Check PCT 1.0 status ####"
    $KEYPCT = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client\'
    if (Test-Path $KEYPCT) 
    {
        $PCT = Get-ItemProperty $KEYPCT
        if ($SSL30.DisabledByDefault -ne 0 -or $PCT.Enabled -eq 0) 
        {
            Write-Host "PCT 1.0 not enabled" -ForegroundColor Green <# Action to perform if the condition is true #>
        }
        else 
        {
            Write-Host "PCT 1.0 enabled" -ForegroundColor Red <# Action when all if and elseif conditions are false #>
        }
    }
