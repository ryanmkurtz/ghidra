# ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ##

# PowerShell port of launch.bat.

[CmdletBinding()]
param(
	[Parameter(Position = 0, ValueFromRemainingArguments = $true)]
	[string[]]$LaunchArgs
)

$ErrorActionPreference = 'Stop'

function Show-Usage {
	$me = Split-Path -Leaf $PSCommandPath
	Write-Host "Usage: $me <mode> <java-type> <name> <max-memory> `"<vmarg-list>`" <app-classname> <app-args>..."
	Write-Host "   <mode>: fg    run as foreground process in current shell"
	Write-Host "           bg    run as background process in new shell"
	Write-Host "           debug run as foreground process in current shell in debug mode (suspend=n)"
	Write-Host "           debug-suspend   run as foreground process in current shell in debug mode (suspend=y)"
	Write-Host "           NOTE: for all debug modes environment variable DEBUG_ADDRESS may be set to"
	Write-Host "                 override default debug address of 127.0.0.1:18001"
	Write-Host "   <java-type>: jdk  requires JDK to run"
	Write-Host "                jre  JRE is sufficient to run (JDK works too)"
	Write-Host "   <name>: application name used for naming console window"
	Write-Host "   <max-memory>: maximum memory heap size in MB (e.g., 768M or 2G).  Use `"`" if default should be used."
	Write-Host "                 This will generally be upto 1/4 of the physical memory available to the OS.  On"
	Write-Host "                 some systems the default could be much less (particularly for 32-bit OS)."
	Write-Host "   <vmarg-list>: pass-thru args (e.g.,  `"-Xmx512M -Dmyvar=1 -DanotherVar=2`") - use"
	Write-Host "                 empty `"`" if vmargs not needed"
	Write-Host "   <app-classname>: application classname (e.g., ghidra.GhidraRun )"
	Write-Host "   <app-args>...: arguments to be passed to the application"
	Write-Host ""
	Write-Host "   Example:"
	Write-Host "      $me debug jdk Ghidra 4G `"`" ghidra.GhidraRun"
	exit 1
}

# Splits a whitespace-delimited string into an array of arguments (mirrors how cmd.exe
# expands an unquoted variable onto the command line).
function Split-VmArgs([string]$value) {
	if ([string]::IsNullOrWhiteSpace($value)) {
		return @()
	}
	return @($value -split '\s+' | Where-Object { $_ -ne '' })
}

# See if we were double clicked or run from a command prompt
$DOUBLE_CLICKED = $false
try {
	$parentId = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop).ParentProcessId
	$parentName = (Get-Process -Id $parentId -ErrorAction Stop).ProcessName
	if ($parentName -eq 'explorer') {
		$DOUBLE_CLICKED = $true
	}
} catch {
	# Best effort only
}

# Directory that contains this script (no trailing slash).
$SUPPORT_DIR = Split-Path -Parent $PSCommandPath

# Ensure Ghidra path doesn't contain illegal characters
if ($SUPPORT_DIR.Contains('!')) {
	Write-Host 'ERROR: Ghidra path cannot contain a "!" character.'
	exit 1
}

#
# Parse arguments
#
$argv = @($LaunchArgs)

$MODE = if ($argv.Count -gt 0) { $argv[0] } else { '' }
$JAVA_TYPE_ARG = if ($argv.Count -gt 1 -and $argv[1] -eq 'jre') { '-java_home' } else { '-jdk_home' }
$APPNAME = if ($argv.Count -gt 2) { $argv[2] } else { '' }
$MAXMEM = if ($argv.Count -gt 3) { $argv[3] } else { '' }
$VMARGS_FROM_CALLER = if ($argv.Count -gt 4) { $argv[4] } else { '' }
$CLASSNAME = if ($argv.Count -gt 5) { $argv[5] } else { '' }
$APP_ARGS = @()
if ($argv.Count -gt 6) {
	$APP_ARGS = $argv[6..($argv.Count - 1)]
}

if ([string]::IsNullOrEmpty($CLASSNAME)) {
	Write-Host "ERROR: Incorrect launch usage - missing argument(s)"
	Show-Usage
}

#
# Production Environment
#
$INSTALL_DIR = Join-Path $SUPPORT_DIR '..'
$CPATH = Join-Path $INSTALL_DIR 'Ghidra\Framework\Utility\lib\Utility.jar'
$LS_CPATH = Join-Path $SUPPORT_DIR 'LaunchSupport.jar'
$DEBUG_LOG4J = Join-Path $SUPPORT_DIR 'debug.log4j.xml'

if (-not (Test-Path -LiteralPath (Join-Path $INSTALL_DIR 'Ghidra\application.properties'))) {
	#
	# Development Environment (Eclipse classes or "gradle jar")
	#
	$INSTALL_DIR = Join-Path $SUPPORT_DIR '..\..\..'
	$CPATH = Join-Path $INSTALL_DIR 'Ghidra\Framework\Utility\bin\main'
	$LS_CPATH = Join-Path $INSTALL_DIR 'GhidraBuild\LaunchSupport\bin\main'
	if (-not (Test-Path -LiteralPath $LS_CPATH)) {
		$CPATH = Join-Path $INSTALL_DIR 'Ghidra\Framework\Utility\build\libs\Utility.jar'
		$LS_CPATH = Join-Path $INSTALL_DIR 'GhidraBuild\LaunchSupport\build\libs\LaunchSupport.jar'
	}
	if (-not (Test-Path -LiteralPath $LS_CPATH)) {
		Write-Host "ERROR: Cannot launch from repo because Ghidra has not been compiled with Eclipse or Gradle."
		exit 1
	}
	$DEBUG_LOG4J = Join-Path $INSTALL_DIR 'Ghidra\RuntimeScripts\support\debug.log4j.xml'
}

# Accumulated VM arguments that this script contributes (mirrors VMARGS_FROM_LAUNCH_BAT)
$VMARGS_FROM_LAUNCH_BAT = [System.Collections.Generic.List[string]]::new()

# This is to force Java to use the USERPROFILE directory for user.home
if ($env:USERPROFILE -and (Test-Path -LiteralPath $env:USERPROFILE)) {
	$VMARGS_FROM_LAUNCH_BAT.Add("-Duser.home=$($env:USERPROFILE)")
}

# check for java based upon PATH
$JAVA_CMD = 'java'
$javaOk = $false
try {
	& $JAVA_CMD -version *> $null
	$javaOk = ($LASTEXITCODE -eq 0)
} catch {
	$javaOk = $false
}

if (-not $javaOk) {
	# check for java based upon JAVA_HOME environment variable
	if ($env:JAVA_HOME) {
		$JAVA_CMD = Join-Path $env:JAVA_HOME 'bin\java.exe'
		try {
			& $JAVA_CMD -version *> $null
			$javaOk = ($LASTEXITCODE -eq 0)
		} catch {
			$javaOk = $false
		}
		if (-not $javaOk) {
			Write-Host "WARNING: JAVA_HOME environment variable is set to an invalid directory: $($env:JAVA_HOME)"
		}
	}
}

if (-not $javaOk) {
	Write-Host ""
	Write-Host "ERROR: The 'java' command could not be found in your PATH or with JAVA_HOME."
	Write-Host "Please refer to the Getting Started document's Troubleshooting section."
	exit 1
}

# Use LaunchSupport to locate supported java runtime
function Get-LsJavaHome {
	$out = & $JAVA_CMD -cp $LS_CPATH LaunchSupport $INSTALL_DIR $JAVA_TYPE_ARG -save 2> $null
	return ($out | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' } | Select-Object -First 1)
}

$LS_JAVA_HOME = Get-LsJavaHome
if ([string]::IsNullOrEmpty($LS_JAVA_HOME)) {
	# No JDK has been setup yet.  Let the user choose one.
	& $JAVA_CMD -cp $LS_CPATH LaunchSupport $INSTALL_DIR $JAVA_TYPE_ARG -ask

	# Now that the user chose one, try again to get the JDK that will be used to launch Ghidra
	$LS_JAVA_HOME = Get-LsJavaHome
	if ([string]::IsNullOrEmpty($LS_JAVA_HOME)) {
		Write-Host ""
		Write-Host "ERROR: Failed to find a supported JDK."
		Write-Host "Please refer to the Getting Started document's Troubleshooting section."
		exit 1
	}
}
$JAVA_CMD = Join-Path $LS_JAVA_HOME 'bin\java'

# Get the configurable environment variables from the launch properties
# Only set them if they are currently undefined
$envvarsOut = & $JAVA_CMD -cp $LS_CPATH LaunchSupport $INSTALL_DIR -envvars
foreach ($line in $envvarsOut) {
	$idx = $line.IndexOf('=')
	if ($idx -lt 0) {
		continue
	}
	$name = $line.Substring(0, $idx)
	$value = $line.Substring($idx + 1)
	if (-not (Test-Path -Path "Env:\$name")) {
		Set-Item -Path "Env:\$name" -Value $value
	}
}

# Get the configurable VM arguments from the launch properties
$VMARGS_FROM_LAUNCH_PROPS = [System.Collections.Generic.List[string]]::new()
$vmargsOut = & $JAVA_CMD -cp $LS_CPATH LaunchSupport $INSTALL_DIR -vmargs
foreach ($line in $vmargsOut) {
	if (-not [string]::IsNullOrWhiteSpace($line)) {
		$VMARGS_FROM_LAUNCH_PROPS.Add($line.Trim())
	}
}

# Set Max Heap Size if specified
if (-not [string]::IsNullOrEmpty($MAXMEM)) {
	$VMARGS_FROM_LAUNCH_BAT.Add("-Xmx$MAXMEM")
}

$BACKGROUND = $false
$DEBUG = $false
$SUSPEND = $false

switch ($MODE) {
	'debug' {
		$DEBUG = $true
	}
	'debug-suspend' {
		$DEBUG = $true
		$SUSPEND = $true
	}
	'fg' {
	}
	'bg' {
		$BACKGROUND = $true
	}
	default {
		Write-Host "ERROR: Incorrect launch usage - invalid launch mode: $MODE"
		exit 1
	}
}

if ($DEBUG) {
	if ([string]::IsNullOrEmpty($env:DEBUG_ADDRESS)) {
		$env:DEBUG_ADDRESS = '127.0.0.1:18001'
	}
	$suspendFlag = if ($SUSPEND) { 'y' } else { 'n' }
	$VMARGS_FROM_LAUNCH_BAT.Add("-Dlog4j.configurationFile=$DEBUG_LOG4J")
	$VMARGS_FROM_LAUNCH_BAT.Add("-agentlib:jdwp=transport=dt_socket,server=y,suspend=$suspendFlag,address=$($env:DEBUG_ADDRESS)")
}

# Assemble the full java command line
$CMD_ARGS = [System.Collections.Generic.List[string]]::new()
foreach ($a in (Split-VmArgs $env:FORCE_JAVA_VERSION)) { $CMD_ARGS.Add($a) }
foreach ($a in (Split-VmArgs $env:JAVA_USER_HOME_DIR_OVERRIDE)) { $CMD_ARGS.Add($a) }
foreach ($a in $VMARGS_FROM_LAUNCH_PROPS) { $CMD_ARGS.Add($a) }
foreach ($a in $VMARGS_FROM_LAUNCH_BAT) { $CMD_ARGS.Add($a) }
foreach ($a in (Split-VmArgs $VMARGS_FROM_CALLER)) { $CMD_ARGS.Add($a) }
$CMD_ARGS.Add('-cp')
$CMD_ARGS.Add($CPATH)
$CMD_ARGS.Add('ghidra.Ghidra')
$CMD_ARGS.Add($CLASSNAME)
foreach ($a in $APP_ARGS) { $CMD_ARGS.Add($a) }

[string[]]$CMD_ARGV = $CMD_ARGS.ToArray()

$exitCode = 0

if ($BACKGROUND) {
	$JAVAW_CMD = "${JAVA_CMD}w"

	Start-Process -FilePath $JAVAW_CMD -ArgumentList $CMD_ARGV -WindowStyle Hidden

	# If our process dies immediately, output something so the user knows to run in debug mode.
	# Otherwise they'll never see any error output from background mode.
	# NOTE: The below check isn't perfect because they might have other javaw's running, but
	# without the PID of the thing we launched, it's the best we can do.
	# Worst case, they just won't see the error message.
	Start-Sleep -Seconds 1
	if (-not (Get-Process -Name 'javaw' -ErrorAction SilentlyContinue)) {
		Write-Host "Exited with error.  Run in foreground (fg) mode for more details."
	}
} else {
	& $JAVA_CMD @CMD_ARGV
	$exitCode = $LASTEXITCODE
}

if ($exitCode -ne 0 -and $DOUBLE_CLICKED) {
	Read-Host "Press <Enter> to continue"
}

exit $exitCode
