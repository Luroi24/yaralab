rule DEADBITS_Acbackdoor_ELF : LINUX MALWARE BACKDOOR
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam M. Swanda"
		id = "82eb41bf-cd1d-5b00-973b-31a79c75cfc0"
		date = "2019-11-29"
		modified = "2019-12-04"
		reference = "https://www.intezer.com/blog-acbackdoor-analysis-of-a-new-multiplatform-backdoor/"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/ACBackdoor_Linux.yara#L1-L41"
		license_url = "N/A"
		logic_hash = "48d741fba86cdfc8aac779d4b3227d45a17e0e9fba74b19820f1b8308bb93322"
		score = 75
		quality = 55
		tags = "LINUX, MALWARE, BACKDOOR"

	strings:
		$ua_str = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" ascii fullword
		$header1 = "Access-Control:" ascii fullword
		$header2 = "X-Access" ascii
		$initd = "/etc/init.d/update-notifier" ascii fullword
		$str001 = "#!/bin/sh -e" ascii fullword
		$str002 = "### BEGIN INIT INFO" ascii fullword
		$str003 = "# Provides:          update-notifier" ascii fullword
		$str004 = "# Required-Start:    $local_fs" ascii fullword
		$str005 = "# Required-Stop:" ascii fullword
		$str006 = "# Default-Start:     S" ascii fullword
		$str007 = "# Default-Stop:" ascii fullword
		$str008 = "### END INIT INFO" ascii fullword
		$str010 = "  *) echo \"Usage: $0 {start|stop|restart|force-reload}\" >&2; ;;" ascii fullword
		$str011 = "esac" ascii fullword
		$str012 = "[ -x /usr/local/bin/update-notifier ] \\" ascii fullword
		$str013 = "    && exec /usr/local/bin/update-notifier" ascii fullword
		$rcd01 = "/etc/rc2.d/S01update-notifier" ascii fullword
		$rcd02 = "/etc/rc3.d/S01update-notifier" ascii fullword
		$rcd03 = "/etc/rc5.d/S01update-notifier" ascii fullword

	condition:
		( uint32be( 0x0 ) == 0x7f454c46 ) and ( ( $ua_str and all of ( $header* ) and $initd and all of ( $rcd* ) ) or ( $ua_str and all of ( $header* ) and 10 of ( $str* ) ) )
}

