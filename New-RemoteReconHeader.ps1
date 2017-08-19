function New-RemoteReconHeader
{
    <#
    .SYNOPSIS Generates a new header file in the post build event for RemoteReconKS
    
    Author: @tifkin_ Lee Christensen
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $AssemblyPath
    )

	$Bytes = Get-Content -Raw -Encoding Byte $AssemblyPath
	$OutputStr = New-Object System.Text.StringBuilder

	$Counter = 1
	foreach($Byte in $Bytes) {
		$null = $OutputStr.Append("0x$('{0:X2}' -f $Byte),") 

		if($Counter % 12 -eq 0) {
			$null = $OutputStr.AppendLine()
			$null = $OutputStr.Append("`t")
		}
		$Counter++
	}

	$null = $OutputStr.Remove($OutputStr.Length-1,1)

	$Source = @'
#ifndef REMOTERECONKSDLL_H_
#define REMOTERECONKSDLL_H_

static const unsigned char RemoteReconKS_dll[] = {
    REPLACE
};

static const unsigned int REMOTERECONKS_dll_len = LENGTH;

#endif
'@

	$Source = $Source -replace 'REPLACE',$OutputStr.ToString()
	$Source = $Source -replace 'LENGTH',$Bytes.Length
	$Source
}
