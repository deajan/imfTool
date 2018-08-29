#!/bin/bash
# Busybox 1.2.9-FRP compatible IMF Client under BSD-3-Clause license

#TODO: if earlier reports exist, try to upload them before creating new ones
#TODO: add report date to uploads / reports
#TODO: deployment could have a date set when to install (actual deployment arguments: install after datetime, stop install after datetime, retry on failure, number of retries
#TODO: tidyup old executables, on success, or on failure after a while
#TODO: Add description in IMF first upload only, also add it to cahier des charges
#OKTODO: Add graphic card output wmic path win32_VideoController get name 
#OKTODO: Add antivirus state WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
#TODO: Smart etat par disque et détails
#TODO: RAM occupé / CPU occupé
#TODO: Roles installés 
#TODO: netstat (netstat -benrst, netstat -abfn)
#TODO: printers (check if wmic does)
#TODO: users s/ localgroup
#TOOO: Dernieres erreurs critiques x5
#TODO: SN ecran ??? WMI / Edid does not work !!! what to do?
#TODO: Dock

# Partially done: works in powershell, need to test for portable and fast conversions
#TODO: filter \& and utf characters from json conversions

PROGRAM="imfClient" # Windows inventory and deployment client
AUTHOR="(C) 2017-2018 by Orsiris de Jong"
CONTACT="http://www.netpower.fr"
PROGRAM_VERSION=2.1.2-dev
PROGRAM_BUILD=2018080601
IS_STABLE=no																	#PROD yes

# Delete logs older than x days, 0 means keeping them forever
DELETE_OLD_LOGS=60																#PROD != 0

_LOGGER_PREFIX=date
_LOGGER_SILENT=false		#PROD true

source "$(dirname $0)/imf_lan.d"
BASE_URL="https://imf.netpower.fr"

############################################################################################ WIP BFG WARNING: REPLACE CLIENT_URL with specific report URL !!!!

#CLIENT_URL="$BASE_URL/$H_C"		#WIP
CLIENT_URL="$BASE_URL/STATREPORTER"

DEPLOY_PATH="$CLIENT_URL/deploy"
RESULT_PATH="$CLIENT_URL/deploy/results"
EXECUTABLES="$SYSTEMDRIVE/IMF/EXECUTABLES"
EXECUTALBES_EXTENSION=exe
IMF_DIRECTORY="$SYSTEMDRIVE/IMF"
IMF_LOGS_DIRECTORY="$IMF_DIRECTORY/LOGS"
IMF_REPORTS_DIRECTORY="$IMF_DIRECTORY/REPORTS"
IMF_WMIC_FILE="imf.wmic"	# PROD non light


# Optional curl options (curl must be given as an external binary)
# -k = ignore certificates, -f = fail silently, -L = follow redirects
CURL_OPTS="-kfL"
# Optional curl proxy (example  fqdn.local:3128)
CURL_PROXY_FQDN=

_LOGGER_SILENT=false		#PROD true
_LEGACY_CODPAGE=CP1252		# MS-ANSI codepage for output from legacy commands

###########################################################################

export LC_ALL=C

## Default umask for file creation
umask 0077

SCRIPT_PID=$$
SCRIPT_ERROR=0

## Default log file until config file is loaded
CURRENT_DIR=`dirname "$0"`
if [ -w "$CURRENT_DIR" ]; then
	LOG_FILE="$CURRENT_DIR/$PROGRAM-$PROGRAM_VERSION.$(date '+%Y%m%dT%H%M%S').log"
elif [ -w "$TEMP" ]; then
	LOG_FILE="$TEMP/$PROGRAM-$PROGRAM_VERSION.$(date '+%Y%m%dT%H%M%S').log"
elif [ -w "$HOME" ]; then
	LOG_FILE="$HOME/$PROGRAM-$PROGRAM_VERSION.$(date '+%Y%m%dT%H%M%S').log"
else
	LOG_FILE="./$PROGRAM-$PROGRAM_VERSION.$(date '+%Y%m%dT%H%M%S').log"
fi

## Default directory where to store temporary run files
if [ -w "$TMP" ]; then
	RUN_DIR="$TMP"
elif [ -w "$TEMP" ]; then
	RUN_DIR="$TEMP"
else
	RUN_DIR=.
fi

function PoorMansRandomGenerator {
	local digits="${1}"		# The number of digits to generate
	local minimum=1
	local maximum
	local n=0
	
	if [ "$digits" == "" ]; then
		digits=5
	fi
	
	# Minimum already has a digit
	for n in $(seq 1 $((digits-1))); do
		minimum=$minimum"0"
		maximum=$maximum"9"
	done
	maximum=$maximum"9"
	
	#n=0; while [ $n -lt $minimum ]; do n=$n$(dd if=/dev/urandom bs=100 count=1 2>/dev/null | tr -cd '0-9'); done; n=$(echo $n | sed -e 's/^0//')
	# bs=19 since if real random strikes, having a 19 digits number is not supported
	while [ $n -lt $minimum ] || [ $n -gt $maximum ]; do
		if [ $n -lt $minimum ]; then
			# Add numbers
			n=$n$(dd if=/dev/urandom bs=19 count=1 2>/dev/null | tr -cd '0-9')
			n=$(echo $n | sed -e 's/^0//')
			if [ "$n" == "" ]; then
				n=0
			fi
		elif [ $n -gt $maximum ]; then
			n=$(echo $n | sed 's/.$//')
		fi
	done
	echo $n
}

# Initial TSTMAP value before function declaration
TSTAMP=$(date '+%Y%m%dT%H%M%S')

# Set error exit code if a piped command fails
set -o pipefail

# Sub function of Logger
function _Logger {
	local logValue="${1}"		# Log to file
	local stdValue="${2}"		# Log to screeen
	local toStdErr="${3:-false}"	# Log to stderr instead of stdout

	if [ "$logValue" != "" ]; then
		echo -e "$logValue" >> "$LOG_FILE"

		# Build current log file for alerts if we have a sufficient environment
		
		# Replaced ${FUNCNAME[0]} with "_Logger" since Busybox does not handle ${FUNCNAME[0]}
		
		if [ "$RUN_DIR/$PROGRAM._Logger.$SCRIPT_PID.$TSTAMP" != "" ]; then
			echo -e "$logValue" >> "$RUN_DIR/$PROGRAM._Logger.$SCRIPT_PID.$TSTAMP"
		fi
	fi
	
	if [ "$stdValue" != "" ] && [ "$_LOGGER_SILENT" != true ]; then
		if [ $toStdErr == true ]; then
			# Force stderr color in subshell
			(>&2 echo -e "$stdValue")
		else
			echo -e "$stdValue"
		fi
	fi
}

# General log function with log levels:

# Environment variables
# _LOGGER_SILENT: Disables any output to stdout & stderr
# _LOGGER_ERR_ONLY: Disables any output to stdout except for ALWAYS loglevel
# _LOGGER_VERBOSE: Allows VERBOSE loglevel messages to be sent to stdout

# Loglevels
# Except for VERBOSE, all loglevels are ALWAYS sent to log file

# CRITICAL, ERROR, WARN sent to stderr, color depending on level, level also logged
# NOTICE sent to stdout
# VERBOSE sent to stdout if _LOGGER_VERBOSE = true
# ALWAYS is sent to stdout unless _LOGGER_SILENT = true
# DEBUG & PARANOIA_DEBUG are only sent to stdout if _DEBUG=yes
# SIMPLE is a wrapper for QuickLogger that does not use advanced functionality
function Logger {
	local value="${1}"		# Sentence to log (in double quotes)
	local level="${2}"		# Log level
	local retval="${3:-undef}"	# optional return value of command

	if [ "$_LOGGER_PREFIX" == "time" ]; then
		prefix="TIME: $SECONDS - "
	elif [ "$_LOGGER_PREFIX" == "date" ]; then
		prefix="$(date '+%Y-%m-%d %H:%M:%S') - "
	else
		prefix=""
	fi

	if [ "$level" == "CRITICAL" ]; then
		_Logger "$prefix($level):$value" "$prefix\e[1;33;41m$value\e[0m" true
		ERROR_ALERT=true
		# ERROR_ALERT / WARN_ALERT is not set in main when Logger is called from a subprocess. Need to keep this flag.
		# Since we run Busybox, ${FUNCNAME} does not exist
		#echo -e "[$retval] in [$(joinString , ${FUNCNAME[@]})] SP=$SCRIPT_PID P=$$\n$prefix($level):$value" >> "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}.error.$SCRIPT_PID.$TSTAMP"
		return
	elif [ "$level" == "ERROR" ]; then
		_Logger "$prefix($level):$value" "$prefix\e[31m$value\e[0m" true
		ERROR_ALERT=true
		#echo -e "[$retval] in [$(joinString , ${FUNCNAME[@]})] SP=$SCRIPT_PID P=$$\n$prefix($level):$value" >> "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}.error.$SCRIPT_PID.$TSTAMP"
		return
	elif [ "$level" == "WARN" ]; then
		_Logger "$prefix($level):$value" "$prefix\e[33m$value\e[0m" true
		WARN_ALERT=true
		#echo -e "[$retval] in [$(joinString , ${FUNCNAME[@]})] SP=$SCRIPT_PID P=$$\n$prefix($level):$value" >> "$RUN_DIR/$PROGRAM.${FUNCNAME[0]}.warn.$SCRIPT_PID.$TSTAMP"
		return
	elif [ "$level" == "NOTICE" ]; then
		if [ "$_LOGGER_ERR_ONLY" != true ]; then
			_Logger "$prefix$value" "$prefix$value"
		fi
		return
	elif [ "$level" == "VERBOSE" ]; then
		if [ $_LOGGER_VERBOSE == true ]; then
			_Logger "$prefix($level):$value" "$prefix$value"
		fi
		return
	elif [ "$level" == "ALWAYS" ]; then
		_Logger "$prefix$value" "$prefix$value"
		return
	elif [ "$level" == "DEBUG" ]; then
		if [ "$_DEBUG" == "yes" ]; then
			_Logger "$prefix$value" "$prefix$value"
			return
		fi
	elif [ "$level" == "PARANOIA_DEBUG" ]; then				#__WITH_PARANOIA_DEBUG
		if [ "$_PARANOIA_DEBUG" == "yes" ]; then			#__WITH_PARANOIA_DEBUG
			_Logger "$prefix$value" "$prefix\e[35m$value\e[0m"	#__WITH_PARANOIA_DEBUG
			return							#__WITH_PARANOIA_DEBUG
		fi								#__WITH_PARANOIA_DEBUG
	elif [ "$level" == "SIMPLE" ]; then
		if [ "$_LOGGER_SILENT" == true ]; then
			_Logger "$preix$value"
		else
			_Logger "$preix$value" "$prefix$value"
		fi
		return
	else
		_Logger "\e[41mLogger function called without proper loglevel [$level].\e[0m" "\e[41mLogger function called without proper loglevel [$level].\e[0m" true
		_Logger "Value was: $prefix$value" "Value was: $prefix$value" true
	fi
}

function DeleteOldLogs {
	local daysToKeep="${1}"				# Days to keep logs
	
	if [ $(IsInteger $daysToKeep) -eq 1 ]; then
		if [ $daysToKeep -eq 0 ]; then
			return 0
		else
			CheckCommand false "Deleting old logs" find "$(dirname "$LOG_FILE")" -iname "$PROGRAM.*.log" -mtime +$daysToKeep -delete
		fi
	else
		Logger "Bogus daysToKeep value given [$daysToKeep]." "WARN"
	fi
}

function CleanUp {
	if [ "$_DEBUG" != "yes" ]; then
		rm -f "$RUN_DIR/$PROGRAM.*.$SCRIPT_PID.$TSTAMP"
	fi
}

# Portable child (and grandchild) kill function tester under Linux, BSD and MacOS X
function KillChilds {
	local pid="${1}" # Parent pid to kill childs
	local self="${2:-false}" # Should parent be killed too ?

	# Paranoid checks, we can safely assume that $pid should not be 0 nor 1
	if [ $(IsInteger "$pid") -eq 0 ] || [ "$pid" == "" ] || [ "$pid" == "0" ] || [ "$pid" == "1" ]; then
		Logger "Bogus pid given [$pid]." "CRITICAL"
		return 1
	fi

	if kill -0 "$pid" > /dev/null 2>&1; then
		#TODO: Warning: pgrep is not native on cygwin, have this checked in CheckEnvironment
		if children="$(pgrep -P "$pid")"; then
			if [[ "$pid" == *"$children"* ]]; then
				Logger "Bogus pgrep implementation." "CRITICAL"
				children="${children/$pid/}"
			fi
			for child in $children; do
				KillChilds "$child" true
			done
		fi
	fi

	# Try to kill nicely, if not, wait 15 seconds to let Trap actions happen before killing
	if [ "$self" == true ]; then
		# We need to check for pid again because it may have disappeared after recursive function call
		if kill -0 "$pid" > /dev/null 2>&1; then
			kill -s TERM "$pid"
			Logger "Sent SIGTERM to process [$pid]." "DEBUG"
			if [ $? != 0 ]; then
				sleep 15
				Logger "Sending SIGTERM to process [$pid] failed." "DEBUG"
				kill -9 "$pid"
				if [ $? != 0 ]; then
					Logger "Sending SIGKILL to process [$pid] failed." "DEBUG"
					return 1
				fi	# Simplify the return 0 logic here
			else
				return 0
			fi
		else
			return 0
		fi
	else
		return 0
	fi
}

function TrapQuit {
	local exitcode

	# Get ERROR / WARN alert flags from subprocesses that call Logger
	if [ -f "$RUN_DIR/$PROGRAM.Logger.warn.$SCRIPT_PID.$TSTAMP" ]; then
		WARN_ALERT=true
	fi
	if [ -f "$RUN_DIR/$PROGRAM.Logger.error.$SCRIPT_PID.$TSTAMP" ]; then
		ERROR_ALERT=true
	fi

	if [ $ERROR_ALERT == true ]; then
		Logger "$PROGRAM finished with errors." "ERROR"
		exitcode=1
	elif [ $WARN_ALERT == true ]; then
		Logger "$PROGRAM finished with warnings." "WARN"
		exitcode=2	# Warning exit code must not force daemon mode to quit
	else
		Logger "$PROGRAM finished." "ALWAYS"
		exitcode=0
	fi
	CleanUp
	KillChilds $SCRIPT_PID > /dev/null 2>&1

	exit $exitcode
}

function CheckAdminPrivileges {
	local exitOnFailure="${1}"			# Defaults to false

	if [ "$LOCAL_OS_FAMILY" == "Windows" ]; then
		net session > /dev/null 2>&1
		if [ $? -ne 0 ]; then
			Logger "Insufficient privileges (not admin or no UAC)." "CRITICAL"
			if [ "$exitOnFailure" == true ]; then
				exit 1
			fi
		fi
	else
		if [[ $(id -u) -ne 0 ]]; then
			Logger "Insufficient privileges (not uid 0)." "CRITICAL"
			if [ "$exitOnFailure" == true ]; then
				exit 1
			fi
		fi
	fi
}

function CheckForBinary {
	local file="${1}"
	local exitOnFailure="${2}"
	
	if ! type "$file" > /dev/null 2>&1; then
		if [ ! -f "$file" ]; then
			Logger "File [$file] not present." "ERROR"
			if [ "$exitOnFailure" == true ]; then
				Logger "Exiting." "CRITICAL"
				exit 1
			fi
		fi
	fi
}

# Function takes a file containing sha256sums and filenames in order to compare them with the actual files
function CheckManifest {
	local file="${1}"			# Manifest file, defaults to file.lst
	
	local sum
	local binary
	
	if [ "$file" == "" ]; then
		file="$CURRENT_DIR/file.lst"
	fi

	while IFS= read -r line || [ -n "$line" ]; do
		if [ "${line:0:1}" == "#" ] || [ "$line" == "" ]; then
			continue
		fi
	
		sum=$(echo "$line" | awk 'BEGIN {FS=":|\t"} {print $1}')
		binary=$(echo "$line" | awk 'BEGIN {FS=":|\t"} {print $2}')
		
		CheckForBinary "$binary" true
		if [ "$(sha256sum "$binary")" != "$(echo "$line" | awk 'BEGIN {FS=":|\t"} {print $1"  "$2}')" ]; then
			Logger "Checksum for [$binary] is not valid, exiting." "CRITICAL"
			exit 1
		fi
	done < "$CURRENT_DIR/$file"
}

# BusyBox compatible version
function IsInteger {
        local value="${1}"

		#if [[ $value =~ ^[0-9]+$ ]]; then
		expr "$value" : "^[0-9]\+$" > /dev/null 2>&1
		if [  $? -eq 0 ]; then
                echo 1
        else
                echo 0
        fi
}

function EscapeDoubleQuotes {
		local value="${1}"
		
		echo "${value//\"/\\\"}"
}

# Function escapes the following characters: {,},(,),\,$
function EscapeCharacters {
	local value="${1}"
	
		echo "$value" | sed 's/[\(\)\{\}\$\\]/\\&/g'
}

## Modified version of https://gist.github.com/cdown/1163649
function UrlEncode {
	local length="${#1}"

	local LANG=C
	for i in $(seq 0 $((length-1))); do
		local c="${1:i:1}"
		case $c in
			[a-zA-Z0-9.~_-])
			printf "$c"
			;;
			*)
			printf '%%%02X' "'$c"
			;;
		esac
	done
}

function UrlDecode {
	local urlEncoded="${1//+/ }"

	printf '%b' "${urlEncoded//%/\\x}"
}

function GetCodePageWindows {
	local chcp
	
	chcp=$(chcp)
	_CODEPAGE="CP${chcp##* }"
}

function GetLocalOS {
	local localOsVar
	local localOsName
	local localOsVer

	# There is no good way to tell if currently running in BusyBox shell. Using sluggish way.
	if ls --help 2>&1 | grep -i "BusyBox" > /dev/null; then
		localOsVar="BusyBox"
	else
		# Detecting the special ubuntu userland in Windows 10 bash
		if grep -i Microsoft /proc/sys/kernel/osrelease > /dev/null 2>&1; then
			localOsVar="Microsoft"
		else
			localOsVar="$(uname -spior 2>&1)"
			if [ $? != 0 ]; then
				localOsVar="$(uname -v 2>&1)"
				if [ $? != 0 ]; then
					localOsVar="$(uname)"
				fi
			fi
		fi
	fi

	case $localOsVar in
		# Android uname contains both linux and android, keep it before linux entry
		*"Android"*)
		LOCAL_OS="Android"
		;;
		*"Linux"*)
		LOCAL_OS="Linux"
		;;
		*"BSD"*)
		LOCAL_OS="BSD"
		;;
		*"MINGW32"*|*"MINGW64"*|*"MSYS"*)
		LOCAL_OS="msys"
		;;
		*"CYGWIN"*)
		LOCAL_OS="Cygwin"
		;;
		*"Microsoft"*)
		LOCAL_OS="WinNT10"
		;;
		*"Darwin"*)
		LOCAL_OS="MacOSX"
		;;
		*"BusyBox"*)
		LOCAL_OS="BusyBox"
		;;
		*)
		if [ "$IGNORE_OS_TYPE" == "yes" ]; then
			Logger "Running on unknown local OS [$localOsVar]." "WARN"
			return
		fi
		if [ "$_OFUNCTIONS_VERSION" != "" ]; then
			Logger "Running on >> $localOsVar << not supported. Please report to the author." "ERROR"
		fi
		exit 1
		;;
	esac

	# Get linux versions
	if [ -f "/etc/os-release" ]; then
		localOsName="$(GetConfFileValue "/etc/os-release" "NAME" true)"
		localOsVer="$(GetConfFileValue "/etc/os-release" "VERSION" true)"
	elif [ "$LOCAL_OS" == "BusyBox" ]; then
		localOsVer=`ls --help 2>&1 | head -1 | cut -f2 -d' '`
		localOsName="BusyBox"
	fi
	
	# Get Host info for Windows
	if [ "$LOCAL_OS" == "msys" ] || [ "$LOCAL_OS" == "BusyBox" ] || [ "$LOCAL_OS" == "Cygwin" ] || [ "$LOCAL_OS" == "WinNT10" ]; then
		localOsVar="$(uname -a)"
		if [ "$PROGRAMW6432" != "" ]; then
			LOCAL_OS_BITNESS=64
			LOCAL_OS_FAMILY="Windows"
		elif [ "$PROGRAMFILES" != "" ]; then
			LOCAL_OS_BITNESS=32
			LOCAL_OS_FAMILY="Windows"
		# Case where running on BusyBox but no program files defined
		elif [ "$LOCAL_OS" == "BusyBox" ]; then
			LOCAL_OS_FAMILY="Unix"
		fi
	# Get Host info for Unix
	else
		LOCAL_OS_FAMILY="Unix"
		if uname -m | grep '64' > /dev/null 2>&1; then
			LOCAL_OS_BITNESS=64
		else
			LOCAL_OS_BITNESS=32
		fi
	fi
	
	# Add a global variable for statistics in installer
	LOCAL_OS_FULL="$localOsVar ($localOsName $localOsVer) $LOCAL_OS_BITNESS-bit $LOCAL_OS_FAMILY"

	if [ "$_OFUNCTIONS_VERSION" != "" ]; then
		Logger "Local OS: [$LOCAL_OS_FULL]." "DEBUG"
	fi
}

function LogHeader {
	Logger "$PROGRAM $PROGRAM_VERSION running on $LOCAL_OS_FULL as PID $SCRIPT_PID" "NOTICE"
	Logger "Logging to $LOG_FILE" "DEBUG"

}
	
# Adds a new value to a config file or updates an existing one
function AddValuesToConfigFile {
	local file="${1}"
	local section="${2}"			# After which line should we add a missing parameter
	local parameterName="${3}"		# Name=Value
	local parameterValue="${4}"
	
	local funcError=false
	
	if ! grep "^$parameterName\( \)\?=" "$file" > /dev/null 2>&1; then
		Logger "Value $parameterName not found. Adding it." "NOTICE"
		sed -i "/$section/a$parameterName=$parameterValue\r" "$file"
		if [ $? != 0 ]; then
			Logger "Could not add $parameterName=$parameterValue to file [$file]." "ERROR"
			funcError=true
		fi
	else
		sed -i "s/$parameterName\( \)\?=\(.*\)/$parameterName=$parameterValue/" "$file"
		if [ $? != 0 ]; then
			Logger "Could not modify $parameterName to value $parameterValue in file [$file]." "ERROR"
			funcError=true
		fi
	fi
	
	if [ $funcError == false ]; then
		if [ "$LOCAL_OS" == "msys" ] || [ "$LOCAL_OS" == "BusyBox" ] || [ "$LOCAL_OS" == "Cygwin" ]; then
			unix2dos -d "$file"
		fi
		return 0
	else
		return 1
	fi
}

function CheckCommand {
	local isErrorGenerating="{1:-true}"		# Will a non zero return code trigger an error ?
	local commandDescription="${2}"			# Command description for logs
	shift ; shift							# Remove first and second arguments from argument list ${@}
	local command="${@}"
	
	Logger "Execute: $commandDescription" "NOTICE"
	Logger "Detail: [$command]." "DEBUG"
	
	eval "${@}" > "$RUN_DIR/$PROGRAM.CheckCommand.$SCRIPT_PID.$TSTAMP.$commandDescription" 2>&1
	retval=$?

	if [ -s "$RUN_DIR/$PROGRAM.CheckCommand.$SCRIPT_PID.$TSTAMP.$commandDescription" ]; then
		if [ "$LOCAL_OS_FAMILY" == "Windows" ]; then
			# Did not find any way to have accents shown right here, depending on the commands that output different codepages!!! Welcome to windows hell
			# Also backslashes are interpreted by echo -n, so we need to escape them since windows commands output backslashes
			Logger "\n$(cat "$RUN_DIR/$PROGRAM.CheckCommand.$SCRIPT_PID.$TSTAMP.$commandDescription" | "$CURRENT_DIR/iconv.exe" -f $_CODEPAGE -t UTF-8 | sed 's/\\/\\\\/g' )" "DEBUG"
		else
			Logger "\n$(cat "$RUN_DIR/$PROGRAM.CheckCommand.$SCRIPT_PID.$TSTAMP.$commandDescription")" "DEBUG"
		fi
	fi
	if [ -f "$RUN_DIR/$PROGRAM.CheckCommand.$SCRIPT_PID.$TSTAMP.$commandDescription" ]; then
		rm -f "$RUN_DIR/$PROGRAM.CheckCommand.$SCRIPT_PID.$TSTAMP.$commandDescription"
	fi

	if [ $retval -ne 0 ]; then
		if [ $isErrorGenerating == true ]; then
			Logger "Error while running [$command] with exit code [$retval]." "ERROR"
		else
			Logger "Command did return exit code [$retval]." "NOTICE"
		fi
		return $retval
	else
		return 0
	fi
}

function oldCheckCommand {	 # WIP
	local commandDescription="${1}"		# Command description for logs
	shift
	local command="${@}"
	
	Logger "Execute: $commandDescription" "NOTICE"
	Logger "Detail: $command" "DEBUG"
	
	eval "$command" > "$RUN_DIR/$PROGRAM.CheckCommand.$SCRIPT_PID.$TSTAMP.$commandDescription" 2>&1
	retval=$?
	
	if [ -s "$RUN_DIR/$PROGRAM.CheckCommand.$SCRIPT_PID.$TSTAMP.$commandDescription" ]; then
		if [ "$LOCAL_OS_FAMILY" == "Windows" ]; then
			(
			
			_LOGGER_PREFIX=none Logger "\n$(cat "$RUN_DIR/$PROGRAM.CheckCommand.$SCRIPT_PID.$TSTAMP.$commandDescription" | "$CURRENT_DIR/iconv.exe" -f $_CODEPAGE -t UTF-8)" "NOTICE"
			)
		else
			(
			_LOGGER_PREFIX=none
			Logger "\n$(cat "$RUN_DIR/$PROGRAM.CheckCommand.$SCRIPT_PID.$TSTAMP.$commandDescription")" "NOTICE"
			)
		fi
	fi
	if [ -f "$RUN_DIR/$PROGRAM.CheckCommand.$SCRIPT_PID.$TSTAMP.$commandDescription" ]; then
		rm -f "$RUN_DIR/$PROGRAM.CheckCommand.$SCRIPT_PID.$TSTAMP.$commandDescription"
	fi

	if [ $retval -ne 0 ]; then
		Logger "Error while running [$command]." "ERROR"
		return $retval
	else
		return 0
	fi
}

# Sets _POWERSHELLEXISTS and POWERSHELLCOMMAND global variables
function CheckForPowershell {
	# First lets detect powershell
	
	if [ $_POWERSHELLEXISTS == true ]; then
		return 0
	fi
	
	if ! type powershell > /dev/null 2>&1; then
		if [ ! -f "$SYSTEMROOT/System32/WindowsPowerShell/v1.0/powershell.exe" ]; then
			Logger "Cannot detect powershell on this system." "ERROR"
			return 1
		else
			POWERSHELLCOMMAND="$SYSTEMROOT/System32/WindowsPowerShell/v1.0/powershell.exe -NonInteractive -NoLogo -NoProfile"
			_POWERSHELLEXISTS=true
		fi
	else
		#TODO: Add execution policy here
		POWERSHELLCOMMAND="powershell -NonInteractive -NoLogo -NoProfile"
		_POWERSHELLEXISTS=true
	fi
	
	if [ "$POWERSHELLCOMMAND" != "" ]; then
		CheckCommand false "Getting powershell version" $POWERSHELLCOMMAND -command \"\\\$PSVersionTable\" > "$RUN_DIR/$PROGRAM.CheckForPowershell.$SCRIPT_PID.$TSTAMP" 2>&1
		if [ -s "$RUN_DIR/$PROGRAM.CheckForPowershell.$SCRIPT_PID.$TSTAMP" ]; then
			Logger "$(cat "$RUN_DIR/$PROGRAM.CheckForPowershell.$SCRIPT_PID.$TSTAMP")" "DEBUG"
		fi
	fi
}

# Uses global POWERSHELLCOMMAND variable
function RunPowerShellScript {
	local commandDescription="${1}"		# Command description for logs
	local scriptPath="${2}"				# Path to script
	shift ; shift
	local arguments="${@}"
	
	local result

	CheckForPowershell

	if [ -f "$scriptPath" ]; then
		command="$POWERSHELLCOMMAND -executionPolicy bypass -file \"$scriptPath\" $arguments"
		Logger "Execution powershell command: $command." "DEBUG"
		eval "$command"
		result=$?
		if [ $result -eq 66 ]; then
			Logger "Order 66 detected. This system does not need [$scriptPath]." "NOTICE"
		elif [ $result -ne 0 ]; then
			Logger "Script [$scriptPath] produced errors." "ERROR"
		fi
		return $result
	else
		Logger "Script [$scriptPath] not found." "ERROR"
	fi
}

function CreateRegistryPath {
	local registryPath="${1}"
	local is64="${2-:false}"			# Should we use 64 bits

	local result
	
	if [ $is64 == true ]; then
		arg="/reg:64"
	fi
	
	CheckCommand true "CreateRegistryPath $registryPath" reg add '$registryPath' /f $arg
	result=$?
	
	return $result
}
	
function SetRegistryKey {
	local regisrtyPath="${1}"
	local name="${2}"
	local value="${3}"
	local valueType="${4}"
	local is64="${5-:false}"			# Should we use 64 bits

	local result
	
	if [ $is64 == true ]; then
		arg="/reg:64"
	fi

	CreateRegistryPath "$registryPath"
	CheckCommand true "SetRegistryKey $registryPath/$value as $valueType" reg add "$registryPath" $arg /v "$name" /t "$valueType" /d "$value" /f $arg
	result=$?
	
	return $result
}

function GetRegistryEntry {
	local registryPath="${1}"			# Path to query, escape '\'
	local value="${2}"					# Key to search
	local is64="${3-:false}"			# Should we use 64 bits
	
	local arg=""
	
	if [ $is64 == true ]; then
		arg="/reg:64"
	fi
	
	local result
	# grep REG ensures that the line contains a REG_SZ or REG_MULTI_SZ or other value format
	# awk '{print substr($0, index($0,$3))}' remvoes the first two columns without leaving trailing empty spaces
	result="$(reg query "$registryPath" $arg /v "$value" 2> "$RUN_DIR/$PROGRAM.GetRegistryEntry.$SCRIPT_PID.$TSTAMP" | grep "$value" | grep "REG" | awk '{print substr($0, index($0,$3))}')"
	if [ $? -eq 0 ]; then
		echo $(EscapeCharacters "$result")
	else
		Logger "Could not get registry entry [$registryPath] [$value]." "ERROR"
		if [ -f "$RUN_DIR/$PROGRAM.GetRegistryEntry.$SCRIPT_PID.$TSTAMP" ]; then
			Logger "Error: $(cat "$RUN_DIR/$PROGRAM.GetRegistryEntry.$SCRIPT_PID.$TSTAMP" | "$CURRENT_DIR/iconv.exe" -f $_CODEPAGE -t UTF-8)" "ERROR"
			return 1
		fi
	fi
}

#WIP same as imf for error handling
#TODO: what if multiple users ? we need to jsonify here
function LoggedOnUserWindows {
	echo "$(wmic computerSystem get UserName /format:List 2> /dev/null | "./iconv.exe" -f CP863 -t UTF-8 | grep ".*=.*" | sed 's/\(.*\)=\(.*\)/\2/g')"
}

# Try to detect hypervisor
function IsVirtualWindows {
	
	# Tested on Win7 ovirt guest
	wmic computerSystem get Manufacturer, Product 2> /dev/null | "$CURRENT_DIR/iconv.exe" -f $_CODEPAGE -t UTF-8 > "$RUN_DIR/$PROGRAM.IsVirtualWindows.$SCRIPT_PID.$TSTAMP"
	if grep "oVirt" "$RUN_DIR/$PROGRAM.IsVirtualWindows.$SCRIPT_PID.$TSTAMP" > /dev/null 2>&1; then
		echo "oVirt"
	fi 
	
	# Tested on Win2012R2 Hyper-V guest
	# HyperV adds Manufacturer = Microsoft Corporation, Product = Virtual Machine to baseboard
	wmic baseboard get Manufacturer, Product 2> /dev/null | "$CURRENT_DIR/iconv.exe" -f $_CODEPAGE -t UTF-8 > "$RUN_DIR/$PROGRAM.IsVirtualWindows.$SCRIPT_PID.$TSTAMP"
	if grep "Microsoft Corporation" "$RUN_DIR/$PROGRAM.IsVirtualWindows.$SCRIPT_PID.$TSTAMP" > /dev/null 2>&1; then
		if grep "Virtual Machine" "$RUN_DIR/$PROGRAM.IsVirtualWindows.$SCRIPT_PID.$TSTAMP" > /dev/null 2>&1; then
			echo "Hyper-V"
		fi
	fi

	# Tested on Win2012R2 VMWare guest, on Win2012 R2 Hyper-V guest, Xen detection is from internet post
	# HyperV adds 'VERSION/ VRTUAL' to bios Version , WMVare adds 'VMWare' to bios SerialNumber, Xen adds 'Xen' to bios version	
	wmic bios get Manufacturer, serialnumber, version 2> /dev/null | "$CURRENT_DIR/iconv.exe" -f $_CODEPAGE -t UTF-8 > "$RUN_DIR/$PROGRAM.IsVirtualWindows.$SCRIPT_PID.$TSTAMP"	

	# Could be KVM / oVirt / Whatever uses SeaBIOS
	if grep -i "SeaBIOS" "$RUN_DIR/$PROGRAM.IsVirtualWindows.$SCRIPT_PID.$TSTAMP" > /dev/null 2>&1; then
		echo "KVM"
	elif grep -i "VMWare" "$RUN_DIR/$PROGRAM.IsVirtualWindows.$SCRIPT_PID.$TSTAMP" > /dev/null 2>&1; then
		echo "VMWare"
	elif grep -i "Xen" "$RUN_DIR/$PROGRAM.IsVirtualWindows.$SCRIPT_PID.$TSTAMP" > /dev/null 2>&1; then
		echo "Xen"
	# Fuzzy detection here
	elif grep "VERSION" "$RUN_DIR/$PROGRAM.IsVirtualWindows.$SCRIPT_PID.$TSTAMP" > /dev/null 2>&1; then
		echo "Hyper-V"
	# Works on Win2012R2 server
	elif grep "VRTUAL" "$RUN_DIR/$PROGRAM.IsVirtualWindows.$SCRIPT_PID.$TSTAMP" > /dev/null 2>&1; then
		echo "Hyper-V"
	else
		echo "Physical / Unknown hypervisor"
	fi
}
#TODO: check to replace all cat file | while with while  done < file

function CSV2JSON_powershell {
	local inputFile="${1}"				# Input csv file
	local outputFile="${2}"				# Output json file
	local separator="${3:-,}"		# Separator, defaults to ','

	CheckForPowershell
	
	if [ $_POWERSHELLEXISTS == false ]; then
		return 1
	fi
																				    		
	eval "$POWERSHELLCOMMAND -command \"(Import-CSV -Delimiter \\\"$separator\\\" \\\"$inputFile\\\" | ConvertTo-Json) + ',' |  Add-Content -Path \\\"$outputFile\\\"\""
	if [ $? -ne 0 ]; then
		Logger "Cannot use CSV2JSON_powershell" "WARN"
		return 1
	fi
}
	
function CSV2JSON_fast {
	local inputFile="${1}"				# Input csv file
	local outputFile="${2}"				# Output json file
	local separator="${3:-,}"		# Separator, defaults to ','
	
	local lineCounter=0
	local numberOfHeadings=0
	local headingsCounter=0
	local elementNumber=0
	
	# Since we do not have arrays in ash, we assign elements via eval "header$number"
	# variables header[0-9]* cannot be declared as local

	echo -e "\t[" >> "$outputFile"
	while IFS= read -r line; do
		if [ "$line" == "" ] || [ "${line:0:1}" == "#" ]; then
			continue
		fi
		
		if [ $lineCounter -eq 0 ]; then
			numberOfHeadings=$(echo $line | awk -F"$separator" {'print NF'})
			while [ $headingsCounter -lt $numberOfHeadings ]; do
				eval "header$headingsCounter=\"$(echo $line | awk -v x=$((headingsCounter+1)) -F"$separator" '{print $x}')\""
				headingsCounter=$((headingsCounter+1))
			done
		else
			echo -e "\t\t{" >> "$outputFile"
			elementNumber=0
			while [ $elementNumber -lt $numberOfHeadings ]; do
				element="$(echo $line | awk -v y=$(($elementNumber+1)) -F"$separator" '{print $y}')"
				
				# \0 should be escaped as \\\0
				# sed has much too much CPU usage to use here
				#element="$(EscapeCharacters "$element")"
				#element="${element//\(/\\(}"
				#element="${element//\)/\\(}"
				#element="${element//\$/\\$}"
				#element="${element//\\(/\\\\}"
				# UTF-8 dependant ? also escapes spaces by \0
				#element="${element//\\0/\\\\0}"
				
				if [ "$element" == "" ]; then
					element="null"
				fi
				
				eval "echo -e \"\\t\\t\\\"\$header$elementNumber\\\" : \\\"$element\\\",\"  >> \"$outputFile\""
				
				elementNumber=$((elementNumber+1))
			done
			
			echo -e "\t\t}," >> "$outputFile"
		fi
		lineCounter=$((lineCounter+1))
	done < "$inputFile"
	echo -e "\t]," >> "$outputFile"
}

function CSV2JSON_portable {
	local inputFile="${1}"				# Input csv file
	local outputFile="${2}"				# Output json file
	local separator="${3:-,}"		# Separator, defaults to ','
	
	local fistLine
	local lineCounter=0
	local numberOfHeadings=0
	local headingsCounter=0
	local elementNumber=0
	local element
	
	# Since we do not have arrays in ash, we assign elements via eval "header$number"
	# variables header[0-9]* cannot be declared as local
	
	
	#echo -e "\t[" >> "$outputFile"
	while IFS= read -r line; do
		if [ "$line" == "" ] || [ "${line:0:1}" == "#" ]; then
			continue
		fi
		
		if [ $lineCounter -eq 0 ]; then
			numberOfHeadings=$(echo $line | awk -F"$separator" {'print NF'})
			firstLine="$line"
		else
			echo -e "\t\t{" >> "$outputFile"
			elementNumber=0
			while [ $elementNumber -lt $numberOfHeadings ]; do
				headerElement="$(echo $firstLine | awk -v y=$(($elementNumber+1)) -F"$separator" '{print $y}')"
				element="$(echo $line | awk -v y=$(($elementNumber+1)) -F"$separator" '{print $y}')"
				
				if [ "$element" == "" ]; then
					element="null"
				fi
				
				echo -e "\t\t\"$headerElement\" : \"$element\"," >> "$outputFile"
				
				elementNumber=$((elementNumber+1))
			done
			
			echo -e "\t\t}," >> "$outputFile"
		fi
		lineCounter=$((lineCounter+1))
	done < "$inputFile"
	
	# Add [ ] if more than one item in list
	if [ $lineCounter -gt 2 ]; then
		sed -i.tmp '1s/^/\t[\n/' "$outputFile"
		echo -e "\t]," >> "$outputFile"
	fi
}

function CreateWMICReport {
	local wmicFile="${1}"			# File containing Get Attributes
	local assetFile="${2}"			# Asset file
	
	local command
	local section
	local result
	
	if [ ! -f "$wmicFile" ]; then
		Logger "Wmic file [$wmicFile] not found." "ERROR"
		return 1
	fi
	
	
	#TODO: history if last asset file did not upload successfully #WIP: unnecessary since elder files contain timestamp
	if [ -f "$assetFile" ]; then
		CheckCommand false "Delete previous asset file" rm -f "$assetFile"
	fi
	
	# Open JSON file
	echo "{" >> "$assetFile"

	echo -e "\t\"IMF\" : \"$(GetRegistryEntry 'HKLM\SOFTWARE\Imf\{58ed4e62-c91a-4632-bd4f-b16b00b54a11}' "IMF" "true")\"," >> "$assetFile"
	echo -e "\t\"IMF_PACKAGE\" : \"$(GetRegistryEntry 'HKLM\SOFTWARE\Imf\{58ed4e62-c91a-4632-bd4f-b16b00b54a11}' "IMF_PACKAGE" "true")\"," >> "$assetFile"
	echo -e "\t\"test\" : \"$(GetRegistryEntry 'HKLM\SOFTWARE\7-Zip' "Path" "true")\"," >> "$assetFile"
	echo -e "\t\"CurrentUser\" : \"$(LoggedOnUserWindows)\"," >> "$assetFile" 
	echo -e "\t\"IsVirtual\" : \"$(IsVirtualWindows)\"," >> "$assetFile"
	
	if [ $FULL_INVENTORY == true ]; then
		cat "$wmicFile" | while IFS= read -r line; do
			#TODO: if line begins with '#', ignore it
			if [ "${line:0:1}" == "#" ] || [ "$line" == "" ]; then
				continue
			fi
			
			rm -f "$RUN_DIR/$PROGRAM.CreateWMICReportErrors.$SCRIPT_PID.$TSTAMP"
			
			section="$(EscapeDoubleQuotes "${line%get*}")"	
	
			command="wmic $line /format:list > \"$RUN_DIR/$PROGRAM.CreateWMICReportOutput.$SCRIPT_PID.$TSTAMP\" 2> \"$RUN_DIR/$PROGRAM.CreateWMICReportErrors.$SCRIPT_PID.$TSTAMP\""

			Logger "WMIC Command [wmic $line]." "DEBUG"
			eval "$command"
			result=$?
			
			if [ -s "$RUN_DIR/$PROGRAM.CreateWMICReportErrors.$SCRIPT_PID.$TSTAMP" ]; then
				if [ $result -ne 0 ]; then
					Logger "Wmic command [$line] returned with errors." "ERROR"
				else
					Logger "Wmic command [$line] returned with warnings." "WARN"
				fi
				Logger "$(cat "$RUN_DIR/$PROGRAM.CreateWMICReportErrors.$SCRIPT_PID.$TSTAMP")" "WARN"
			else
				# wmic outputs as UTF-16
				# Adds two lines at beginning and end of the file (sed '1d2d' removes two empty lines, tac reverses file so we remove ending lines too before reversing it again
				# sed 1d removes first line, sed '1s/.*/{/' replaces first line with {. After this we use to tac to reverse the file and do the same at its end
				# sed ':a;N;$!ba;s/\n\n/\n},\n{/g' replaces multiple empty lines (separator) with },{
				# separators between blocks are two lines too
				# sed 's/\(.*\)/\t\1/g' adds a tab to every line
				# sed 's/\"/\\\"/g' = escape all doublequotes
				# sed 's/&amp;/\&/g' = replace '&amp;' with '&'
				# sed 's/\(.*\)=\(.*\)/\t\t\"\1\" : \"\2\",/g' adds doublequotes around values and replaces = with :
				# sed 's/\(.*\)/\t\t\1/g' indents by tabs
				#./iconv.exe -f UTF-16 -t UTF-8 test | sed '1d' | sed '1s/.*/{/' | tac | sed '1d' | sed '1s/.*/},/' | tac |  sed ':a;N;$!ba;s/\n\n/\n},\n{/g'
				"$CURRENT_DIR/iconv.exe" -f UTF-16 -t UTF-8 "$RUN_DIR/$PROGRAM.CreateWMICReportOutput.$SCRIPT_PID.$TSTAMP" | sed '1d' | sed '1s/.*/{/' | tac | sed '1d' | sed '1s/.*/},/' | tac |  sed ':a;N;$!ba;s/\n\n/\n},\n{/g' > "$RUN_DIR/$PROGRAM.CreateWMICReportOutputFormatted.$SCRIPT_PID.$TSTAMP"
				sed 's/\"/\\\"/g' "$RUN_DIR/$PROGRAM.CreateWMICReportOutputFormatted.$SCRIPT_PID.$TSTAMP" | sed 's/&amp;/\&/g' | sed 's/\(.*\)=\(.*\)/\t\"\1\" : \"\2\",/g'  | sed 's/\(.*\)/\t\t\1/g' > "$RUN_DIR/$PROGRAM.CreateWMICReportOutputFormatted2.$SCRIPT_PID.$TSTAMP"
			
				echo -e "\t\"$section\": [" >> "$assetFile"
				cat "$RUN_DIR/$PROGRAM.CreateWMICReportOutputFormatted2.$SCRIPT_PID.$TSTAMP" >> "$assetFile"
				echo -e "\t ]," >> "$assetFile"
			fi	
		done
	fi
	
	echo "}" >> "$assetFile"
}

##Actual program ################################################################################



# Curl function assumes curl binary in current_dir

function CurlGetFile {
	local remoteFile="${1}"					# URL of remote file
	local localFile="${2}"					# Full path and name of local file
	local retries="${3}"					# How many times do we retry (defaults to 3)
	local waitTime="${4}"					# Time between retries (defaults to 3)

	if [ $(IsInteger $retries) -eq 0 ]; then
		retries=3
	fi

	if [ $(IsInteger $waitTime) -eq 0 ]; then
		waitTime=3
	fi
	
	local tries=0
	local success=false
	
	local opts="$CURL_OPTS"
	local proxyOpts="$CURL_PROXY_FQDN"
	
	if [ -f "$localFile" ]; then	
		opts="$opts -z \"$localFile\" -o \"$localFile\""
	else
		opts="$opts -o \"$localFile\""
	fi
	
	if [ "$proxyOpts" != "" ]; then



		proxyOpts="-x $proxyOpts"
	fi
	
	Logger "Downloading $remoteFile" "NOTICE"
	
	while [ $tries -le $retries ] && [ $success == false ]; do
		CheckCommand true "CurlGetFile" "$CURRENT_DIR/curl.exe" --digest --user $H_U:$H_P "$remoteFile" $opts $proxyOpts
		if [ $? -eq 0 ]; then
			success=true
		else
			Logger "Get file [$remoteFile] failed], trying without proxy setting." "NOTICE"
			CheckCommand true "CurlGetFile" "$CURRENT_DIR/curl.exe" --digest --user $H_U:$H_P "$remoteFile" $opts
			if [ $? -eq 0 ]; then
				success=true
			else
				Logger "Get file [$remoteFile] failed." "ERROR"
			fi
		fi
		
		if [ $success == false ] && [ $tries -lt $retries ]; then
			Logger "Trying again in [$waitTime] seconds." "WARN"
			sleep $waitTime
		fi
		tries=$((tries+1))
	done
	if [ $success == true ]; then
		return 0
	else
		return 1
	fi
}

function CurlUploadFile {
	local localFile="${1}"
	local remoteFile="${2}"
	local retries="${3}"					# How many times do we retry (defaults to 3)
	local waitTime="${4}"					# Time between retries (defaults to 3)

	if [ $(IsInteger $retries) -eq 0 ]; then
		retries=3
	fi
	

	if [ $(IsInteger $waitTime) -eq 0 ]; then
		waitTime=3
	fi
	
	local tries=0
	local success=false
	
	local opts="$CURL_OPTS"
	local proxyOpts="$CURL_PROXY_FQDN"

	if [ "$proxyOpts" != "" ]; then
		proxyOpts="-x $proxyOpts"
	fi

	while [ $tries -le $retries ] && [ $success == false ]; do
		CheckCommand true "CurlUploadFile" "$CURRENT_DIR/curl" --digest --user $H_U:$H_P -T "$localFile" "$remoteFile" $opts $proxyOpts
		if [ $? -eq 0 ]; then
			success=true
		else
			Logger "Uploading file [$remoteFile] failed], trying without proxy setting." "NOTICE"
			CheckCommand true "CurlUploadFile" "$CURRENT_DIR/curl" --digest --user $H_U:$H_P -T "$localFile" "$remoteFile" $opts
			if [ $? -eq 0 ]; then
				success=true
			else
				Logger "Uploading file [$remoteFile] failed." "ERROR"
			fi
		fi
		
		if [ $success == false ] && [ $tries -lt $retries ]; then
			Logger "Trying again in [$waitTime] seconds." "WARN"
			sleep $waitTime
		fi
		tries=$((tries+1))
	done
	if [ $success == true ]; then
		return 0
	else
		return 1
	fi
}

# Sets global variable FILELIST
function CurlListDirectory {
	local remoteDirectory="${1}"
	local retries="${3}"					# How many times do we retry (defaults to 3)
	local waitTime="${4}"					# Time between retries (defaults to 3)

	if [ $(IsInteger $retries) -eq 0 ]; then
		retries=3
	fi
	
	if [ $(IsInteger $waitTime) -eq 0 ]; then
		waitTime=3
	fi
	
	local tries=0
	local success=false
	
	local opts="$CURL_OPTS"
	local proxyOpts="$CURL_PROXY_FQDN"
	
	if [ "$proxyOpts" != "" ]; then
		proxyOpts="-x $proxyOpts"
	fi

	while [ $tries -le $retries ] && [ $success == false ]; do
		CheckCommand true "CurlListDirectory" 'FILELIST=$("$CURRENT_DIR/curl.exe" --digest --user $H_U:$H_P "$remoteDirectory" -X PROPFIND -H "Depth: 1" $opts $proxyOpts | grep -i "<D:href>" | sed -e "s/<D:href>\(.*\)<\/D:href>/\1/" | sed "/\/$/d")'
		if [ $? -eq 0 ]; then
			success=true
		else
			Logger "Get directory from [$remoteDirectory] failed, trying without proxy setting." "NOTICE"
			CheckCommand true "CurlListDirectory" 'FILELIST=$("$CURRENT_DIR/curl.exe" --digest --user $H_U:$H_P "$remoteDirectory" -X PROPFIND -H "Depth: 1" $opts | grep -i "<D:href>" | sed -e "s/<D:href>\(.*\)<\/D:href>/\1/" | sed "/\/$/d")'
			if [ $? -eq 0 ]; then
				success=true
			else
				Logger "Get file [$remoteDirectory] failed." "ERROR"
			fi
		fi
		
		if [ $success == false ] && [ $tries -lt $retries ]; then
			Logger "Trying again in [$waitTime] seconds." "WARN"
			sleep $waitTime
		fi
		tries=$((tries+1))
	done
	if [ $success == true ]; then
		return 0
	else
		return 1
	fi
}

function PrepareInstall {
	local executablePath="${1}"
	
	find "$executablePath" -iname "*.exe" > "$RUN_DIR/$PROGRAM.PrepareInstall.$SCRIPT_PID.$TSTAMP" 2> /dev/null
	cat "$RUN_DIR/$PROGRAM.PrepareInstall.$SCRIPT_PID.$TSTAMP" | while IFS= read -r file; do
		if [ -f "$file.success.$COMPUTERNAME" ]; then
			Logger "Skipping installation of [$file] since it already completed successfully." "NOTICE"
		elif [ -f "$file.failed.$COMPUTERNAME" ]; then
			Logger "Skipping installation of [$file] since it already has been tried without success." "NOTICE"
		else
			Logger "Launching installation of [$file]." "NOTICE"
			Install "$file"
		fi
	done
	rm -f "$RUN_DIR/$PROGRAM.PrepareInstall.$SCRIPT_PID.$TSTAMP"
}

function Install {
	local executable="${1}"

	"$EXECUTABLES/$executable" > "$RUN_DIR/$PROGRAM.Install.$SCRIPT_PID.$TSTAMP" 2>&1
	retval=$?
	
	if [ -f "$RUN_DIR/$PROGRAM.Install.$SCRIPT_PID.$TSTAMP" ]; then
		if [ "$LOCAL_OS_FAMILY" == "Windows" ]; then
			Logger "\n$(cat "$RUN_DIR/$PROGRAM.Install.$SCRIPT_PID.$TSTAMP" | "$CURRENT_DIR/iconv.exe" -f  $_CODEPAGE -t UTF-8)" "NOTICE"
		else
			Logger "\n$(cat "$RUN_DIR/$PROGRAM.Install.$SCRIPT_PID.$TSTAMP")" "NOTICE"
		fi
		
		if [ $retval -eq 0 ]; then
			echo $(date) > "$EXECUTABLES/$executable.success.$COMPUTERNAME"
			cat "$RUN_DIR/$PROGRAM.Install.$SCRIPT_PID.$TSTAMP" >> "$executable.success.$COMPUTERNAME"
			Logger "Successfully installed [$file]." "NOTICE"
			CurlUploadFile "$EXECUTABLES/$executable.success.$COMPUTERNAME" "$RESULT_PATH/$(basename "$EXECUTABLES/$executable.success.$COMPUTERNAME")"
		else
			echo $(date) > "$EXECUTABLES/$executable.failed.$COMPUTERNAME"
			cat "$RUN_DIR/$PROGRAM.Install.$SCRIPT_PID.$TSTAMP" >> "$executable.failed.$COMPUTERNAME"
			Logger "Failed to install [$file]." "NOTICE"
			CurlUploadFile "$EXECUTABLES/$executable.failed.$COMPUTERNAME" "$RESULT_PATH/$(basename "$EXECUTABLES/$executable.failed.$COMPUTERNAME")"
		fi
		rm -f "$RUN_DIR/$PROGRAM.Install.$SCRIPT_PID.$TSTAMP"
		
		return $retval
	fi
}

function GetCommandlineArguments {
	for i in "$@"; do
		case $i in
			--silent)
			_LOGGER_SILENT=true
			;;
			--no-inventory)
			INVENTORY=false
			;;
			--quick-inventory)
			FULL_INVENTORY=false
			;;
			--no-deployment)
			DEPLOYMENT=false
			;;
			--help|-h|-?|/?|/help|/h)
			Usage
			exit 127
			;;
		esac
	done
}

function Usage {
	echo "$PROGRAM $PROGRAM_VERSION $PROGRAM_BUILD"
	echo "$AUTHOR"
	echo "$CONTACT"
	echo ""
	echo "Usage: $0 [OPTIONS]"
	echo ""
	echo "OPTIONS:"

	echo "--no-inventory             Do not make an inventory"
	echo "--no-deployment            Do not deploy files from server"
	echo "--quick-inventory          Only do a quick inventory"
	echo "--silent                   Do not output to stdout, used for cron jobs"
	exit 128
}

#################################################################################################
# Script entry point (place installer instructions here)

LEGACY_INVENTORY=false	#PROD
INVENTORY=true
DEPLOYMENT=true
FULL_INVENTORY=true
_POWERSHELLEXISTS=false
WARN_ALERT=false
ERROR_ALERT=false

TSTAMP=$(date '+%Y%m%dT%H%M%S').$(PoorMansRandomGenerator 5)
GetCodePageWindows
trap TrapQuit TERM EXIT INT


GetCommandlineArguments "$@"

cd "$CURRENT_DIR"

if [ ! -d "$IMF_LOGS_DIRECTORY" ]; then
	CheckCommand false "Create log directory" mkdir --parents "$IMF_LOGS_DIRECTORY"
fi

if [ ! -d "$IMF_REPORTS_DIRECTORY" ]; then
	CheckCommand false "Create reports directory" mkdir --parents "$IMF_REPORTS_DIRECTORY"
fi

if [ -w "$IMF_LOGS_DIRECTORY" ]; then
	LOG_FILE="$IMF_LOGS_DIRECTORY/$PROGRAM-$PROGRAM_VERSION.$(date '+%Y%m%dT%H%M%S').log"
fi

GetLocalOS
LogHeader
CheckAdminPrivileges true
CheckManifest
DeleteOldLogs $DELETE_OLD_LOGS

if [ $INVENTORY == true ]; then
	Logger "Executing inventory tool." "NOTICE"
	CheckForPowershell

	INVENTORY_DATE=$(date '+%Y%m%dT%H%M%S')
	
	# Legacy LSPUSH Inventory

	if [ $LEGACY_INVENTORY == true ]; then
		CheckCommand true "Launch legacy inventory tool" "$CURRENT_DIR/lspush.exe" /folder "$CURRENT_DIR"
		# Using wildcard because lspush creates a filename as (DOMAIN|WORKGROUP)-NETBIOSNAME where DOMAIN can't be guessed via script
		LSPUSH_FILENAME=`find ./ -mindepth 1 -maxdepth 1 -iname "*$COMPUTERNAME.ls.txt"`
		CheckCommand true "Upload inventory file" CurlUploadFile "$LSPUSH_FILENAME" "$CLIENT_URL/$LSPUSH_FILENAME"
		if [ $? == 0 ]; then
			CheckCommand true "Remove legacy inventory file" rm -f "$LSPUSH_FILENAME"
		fi
	fi
	# WIP: filenames are for STATREPORTER as client.computername.report.json but should include dates
	
	
	# IMF Inventory
	CreateWMICReport "$CURRENT_DIR/$IMF_WMIC_FILE" "$IMF_REPORTS_DIRECTORY/$H_C.$COMPUTERNAME.ASSET.$INVENTORY_DATE.JSON"

	RunPowerShellScript "Get Exchange Statistics" "$CURRENT_DIR/powershell/imf_exchange.ps1" -outputFileName \"$IMF_REPORTS_DIRECTORY/$H_C.$COMPUTERNAME.EXCHANGE.$INVENTORY_DATE.JSON\"
	RunPowerShellScript "Get Hyper-V Statistics" "$CURRENT_DIR/powershell/imf_hyperv.ps1" -outputFileName \"$IMF_REPORTS_DIRECTORY/$H_C.$COMPUTERNAME.HYPERV.$INVENTORY_DATE.JSON\"
	RunPowerShellScript "Get RDS Statistics" "$CURRENT_DIR/powershell/imf_rds.ps1" -outputFileName \"$IMF_REPORTS_DIRECTORY/RDS.JSON\"

	if [ -f "$IMF_REPORTS_DIRECTORY/ASSET.JSON" ]; then
		CheckCommand true "Upload inventory files" CurlUploadFile "$IMF_REPORTS_DIRECTORY/ASSET.JSON" "$CLIENT_URL/$H_C.$COMPUTERNAME.ASSET.$INVENTORY_DATE.JSON"
	fi
	if [ -f "$IMF_REPORTS_DIRECTORY/EXCHANGE.JSON" ]; then
		CheckCommand true "Upload inventory files" CurlUploadFile "$IMF_REPORTS_DIRECTORY/$H_C.$COMPUTERNAME.EXCHANGE.$INVENTORY_DATE.JSON" "$CLIENT_URL/$H_C.$COMPUTERNAME.EXCHANGE.$INVENTORY_DATE.JSON"
	fi
	if [ -f "$IMF_REPORTS_DIRECTORY/HYPERV.JSON" ]; then
		CheckCommand true "Upload inventory files" CurlUploadFile "$IMF_REPORTS_DIRECTORY/$H_C.$COMPUTERNAME.HYPERV.$INVENTORY_DATE.JSON" "$CLIENT_URL/$H_C.$COMPUTERNAME.HYPERV.$INVENTORY_DATE.JSON"
	fi
	if [ -f "$IMF_REPORTS_DIRECTORY/RDS.JSON" ]; then
		CheckCommand true "Upload inventory files" CurlUploadFile "$IMF_REPORTS_DIRECTORY/$H_C.$COMPUTERNAME.RDS.$INVENTORY_DATE.JSON" "$CLIENT_URL/$H_C.$COMPUTERNAME.RDS.$INVENTORY_DATE.JSON"
	fi
fi

if [ $DEPLOYMENT == true ]; then

	# Deployment

	if [ ! -d "$EXECUTABLES" ]; then
		CheckCommand true "Create exec dir" mkdir --parents "$EXECUTABLES"
	fi


	CurlListDirectory "$DEPLOY_PATH"
	for i in $(echo $FILELIST); do
		localFile="$(UrlDecode ${i##*/})"
		if echo "$i" | grep -i ".lst$" > /dev/null 2>&1; then
			CurlGetFile "$BASE_URL/$i" "$EXECUTABLES/$localFile"
			if grep $COMPUTERNAME "$EXECUTABLES/$localFile" > /dev/null 2>&1 || grep '*' "$EXECUTABLES/$localFile" > /dev/null 2>&1; then
				if [ ! -f "$EXECUTABLES/$localFile.success.$COMPUTERNAME" ] && [ ! -f "$EXECUTABLES/$localFile.failed.$COMPUTERNAME" ]; then
					CurlGetFile "$BASE_URL/${i%*.lst}.$EXECUTALBES_EXTENSION" "/$EXECUTABLES/${localFile%*.lst}.$EXECUTALBES_EXTENSION"
				fi
			else
				Logger "Computer not in list for [$localFile]" "NOTICE"
			fi
		fi
	done
	PrepareInstall "$EXECUTABLES"

fi

CleanUp

exit