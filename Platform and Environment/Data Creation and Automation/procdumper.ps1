<#
    Run multiple procdump processes - use when there are multiple processes of the same name that you need to get dumps of

    Guy Leech, June 2016
#>

<#
.SYNOPSIS

Run SysInternals procdump utility for multiple processes of the same name which it does not do itself

.DESCRIPTION

Allows monitoring of multiple processes and runs in a loop so will pick up newly launched processes of the specified name too

.PARAMETER Processes

A comma separated list of process names to use (without the .exe extension).

.PARAMETER procdump

The full path to the procdump.exe utility. Available at http://live.sysinternals.com/procdump.exe

.PARAMETER dumpFolder

The folder where the dump files will be created, in a sub-folder created for the user of each process monitored. The default is the working directory when the script is run.

.PARAMETER highCPU

The CPU usage above which dumps will be taken if it stays above this level for 10 seconds (or whatever value is passed via the -consecutive argument)

.PARAMETER dumps

The number of dumps to write. The default is 5.

.PARAMETER sleepFor

The number of seconds to sleep for before checking if there are any new processes to monitor. The default is 300 seconds (5 minutes). Specify 0 for a one time operation.

.PARAMETER consecutive

The number of seconds that the CPU has to exceed the value specified via the -highCPU value. The default is 10 seconds.

.PARAMETER hang

Produce a dump if the process has hung window

.PARAMETER exception

Produce a dump if the process generates an unhandled exception. Useful to capture dump files if Windows Error Reporting is not configured.

.PARAMETER includeUsers

Only monitor processes owned by users in this comma separated list of users

.PARAMETER excludeUsers

Only monitor processes owned by users not in this comma separated list of users

.EXAMPLE

& .\ProcDumper.ps1 -Procdump 'c:\program files\systinternal\procdump.exe' -highCpu 95 -processes excel,winword -dumpFolder c:\temp\dumps

Produce dumps if excel.exe or winword.exe processes consume more than 95% for 10 consecutive seconds and write them to user specific folders in c:\temp\dumps

.EXAMPLE

& .\ProcDumper.ps1 -Procdump 'c:\program files\systinternal\procdump.exe' -exception -processes iexplore -dumpFolder c:\temp\dumps -excludeUsers administrator

Produce dumps if iexplore.exe processes generate an unhandled exception, as long as they are not being run by administrator, and write them to user specific folders in c:\temp\dumps

.NOTES

Run with -verbose to get more information as to what is happening in the script

.LINK

https://technet.microsoft.com/en-gb/sysinternals/dd996900

#>

[CmdletBinding()]

Param
(
    [Parameter(Mandatory=$true)]
    [string]$procdump , ## path to procdump.exe
    [Parameter(Mandatory=$true)]
    [string[]]$processes ,
    [string]$dumpFolder = '.' , ## be careful if this is PVS!
    [int]$highCpu = 0 ,
    [int]$dumps = 5 ,
    [int]$sleepFor = 300 ,
    [int]$consecutive = 10 ,
    [switch]$hang ,
    [switch]$exception ,
    [string[]]$includeUsers ,
    [string[]]$excludeUsers 
)

[System.Collections.ArrayList]$pids = @()
[int]$counter = 1

do
{
    ## Check if pids still alive and remove if not - work backwards as removing
    For( $index = $pids.Count - 1 ; $index -ge 0 ; $index-- )
    {
        $thispid = $pids[$index]
        $proc = Get-Process -id $thispid -ErrorAction SilentlyContinue
        if( ! $proc )
        {
            Write-Verbose "$(Get-Date) : Pid $thispid no longer running"
            $pids.RemoveAt($index)
        }
    }

    Write-Verbose "$(Get-Date) : got $($pids.Count) processes in array"

    Get-Process | ?{ $processes -contains $_.ProcessName } | %{
        if( $pids -notcontains $_.Id )
        {
            ## Get owner so can make user specific dump folder
            $username = (Get-wmiobject -Class Win32_Process -Filter "Processid = $($_.id)").GetOwner() | select -ExpandProperty User
            [bool]$doThisOne = $true

            if( ( $includeUsers.Count -gt 0 -and $includeUsers -notcontains $username ) `
                -or ( $excludeUsers.Count -gt 0 -and $excludeUsers -contains $username ) )
            {
                $doThisOne = $false
            }

            if( $doThisOne )
            {
                $userfolder = $dumpFolder + '\' + $username
                if( ! (Test-Path $userfolder ) )
                {
                    $null = md $userfolder
                }
                [string]$arguments = '-accepteula -ma -l '
                if( $hang )
                {
                     $arguments += '-h '
                }
                if( $highCpu -gt 0 )
                {
                    $arguments += "-c $highCpu -u -s $consecutive "
                }
                if( $exception )
                {
                    $arguments += '-e '
                }
                $arguments += " -n $dumps $($_.Id)"

                Write-Verbose "$counter : $(Get-Date) monitoring $($_.Name) pid $($_.id) user $username"
                Start-Process -FilePath $procdump -ArgumentList $arguments -WorkingDirectory $userFolder
                if( $? )
                {
                    $null = $pids.Add( $_.Id )
                    $counter++
                }
            }
            else
            {
                Write-Verbose ( "Excluding {0} (pid {1}) for user {2}" -f $_.Name , $_.Id , $username )
            }
        }
        else
        {
            Write-Verbose "$counter : $(Get-Date) already monitoring $($_.Name) $($_.id)"
        }
    }

    Write-Verbose "Sleeping for $sleepFor seconds ..."

    Start-Sleep -Seconds $sleepFor
} while( $sleepFor -gt 0 )