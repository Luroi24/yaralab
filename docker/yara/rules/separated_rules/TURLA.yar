rule SIGNATURE_BASE_Turla_APT_Srsvc : TURLA FILE
{
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		author = "Florian Roth (Nextron Systems)"
		id = "951ee9f8-1ab0-5fd5-be9b-053ec82f6ea2"
		date = "2016-06-09"
		modified = "2023-12-05"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_turla.yar#L10-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "76bd2aacde66114090d1c1767da64728219230964a0bc78a5d830819c46bac3a"
		score = 75
		quality = 85
		tags = "TURLA, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		family = "Turla"
		hash1 = "65996f266166dbb479a42a15a236e6564f0b322d5d68ee546244d7740a21b8f7"
		hash2 = "25c7ff1eb16984a741948f2ec675ab122869b6edea3691b01d69842a53aa3bac"

	strings:
		$x1 = "SVCHostServiceDll.dll" fullword ascii
		$s2 = "msimghlp.dll" fullword wide
		$s3 = "srservice" fullword wide
		$s4 = "ModStart" fullword ascii
		$s5 = "ModStop" fullword ascii

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 20KB and ( 1 of ( $x* ) or all of ( $s* ) ) ) or ( all of them )
}

rule SIGNATURE_BASE_Turla_APT_Malware_Gen1 : TURLA FILE
{
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		author = "Florian Roth (Nextron Systems)"
		id = "7ead2da1-3544-5a26-8767-6d3f29de8b96"
		date = "2016-06-09"
		modified = "2023-12-05"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_turla.yar#L33-L71"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "3676d01d5e4044fd49292eb7b4376ff90f0a41141f89a19b13c5518b01257be3"
		score = 75
		quality = 85
		tags = "TURLA, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		family = "Turla"
		hash1 = "0e1bf347c37fb199886f1e675e372ba55ac4627e8be2f05a76c2c64f9b6ed0e4"
		hash2 = "7206075cd8f1004e8f1f759d46e98bfad4098b8642412811a214c0155a1f08b9"
		hash3 = "fe3ffd7438c0d38484bf02a78a19ea81a6f51b4b3f2b2228bd21974c2538bbcd"
		hash4 = "c49111af049dd9746c6b1980db6e150b2a79ca1569b23ed2cba81c85c00d82b4"
		hash5 = "b62a643c96e2e41f639d2a8ce11d61e6b9d7fb3a9baf011120b7fec1b4ee3cf4"
		hash6 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
		hash7 = "8f2ea0f916fda1dfb771f5441e919c561da5b6334b9f2fffcbf53db14063b24a"
		hash8 = "8dddc744bbfcf215346c812aa569e49523996f73a1f22fe4e688084ce1225b98"
		hash9 = "0c69258adcc97632b729e55664c22cd942812336d41e8ea0cff9ddcafaded20f"
		hash10 = "2b4fba1ef06f85d1395945db40a9f2c3b3ed81b56fb9c2d5e5bb693c230215e2"

	strings:
		$x1 = "too long data for this type of transport" fullword ascii
		$x2 = "not enough server resources to complete operation" fullword ascii
		$x3 = "Task not execute. Arg file failed." fullword ascii
		$x4 = "Global\\MSCTF.Shared.MUTEX.ZRX" fullword ascii
		$s1 = "peer has closed the connection" fullword ascii
		$s2 = "tcpdump.exe" fullword ascii
		$s3 = "windump.exe" fullword ascii
		$s4 = "dsniff.exe" fullword ascii
		$s5 = "wireshark.exe" fullword ascii
		$s6 = "ethereal.exe" fullword ascii
		$s7 = "snoop.exe" fullword ascii
		$s8 = "ettercap.exe" fullword ascii
		$s9 = "miniport.dat" fullword ascii
		$s10 = "net_password=%s" fullword ascii

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( 2 of ( $x* ) or 8 of ( $s* ) ) ) or ( 12 of them )
}

rule SIGNATURE_BASE_Turla_APT_Malware_Gen3 : TURLA FILE
{
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		author = "Florian Roth (Nextron Systems)"
		id = "8cb7d873-e4f9-553e-84e8-dbc0d31f65ab"
		date = "2016-06-09"
		modified = "2023-12-05"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_turla.yar#L110-L150"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "8c24cf71841efc974c8a4d8eb5662137592c1d454821c9beadc50d83cb19333c"
		score = 75
		quality = 85
		tags = "TURLA, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		family = "Turla"
		hash1 = "c49111af049dd9746c6b1980db6e150b2a79ca1569b23ed2cba81c85c00d82b4"
		hash2 = "b62a643c96e2e41f639d2a8ce11d61e6b9d7fb3a9baf011120b7fec1b4ee3cf4"
		hash3 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
		hash4 = "8f2ea0f916fda1dfb771f5441e919c561da5b6334b9f2fffcbf53db14063b24a"
		hash5 = "8dddc744bbfcf215346c812aa569e49523996f73a1f22fe4e688084ce1225b98"
		hash6 = "0c69258adcc97632b729e55664c22cd942812336d41e8ea0cff9ddcafaded20f"
		hash7 = "2b4fba1ef06f85d1395945db40a9f2c3b3ed81b56fb9c2d5e5bb693c230215e2"
		hash8 = "7206075cd8f1004e8f1f759d46e98bfad4098b8642412811a214c0155a1f08b9"
		hash9 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"

	strings:
		$x1 = "\\\\.\\pipe\\sdlrpc" fullword ascii
		$x2 = "WaitMutex Abandoned %p" fullword ascii
		$x3 = "OPER|Wrong config: no port|" fullword ascii
		$x4 = "OPER|Wrong config: no lastconnect|" fullword ascii
		$x5 = "OPER|Wrong config: empty address|" fullword ascii
		$x6 = "Trans task %d obj %s ACTIVE fail robj %s" fullword ascii
		$x7 = "OPER|Wrong config: no auth|" fullword ascii
		$x8 = "OPER|Sniffer '%s' running... ooopppsss...|" fullword ascii
		$s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\5.0\\User Agent\\Post Platform" fullword ascii
		$s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\5.0\\User Agent\\Pre Platform" fullword ascii
		$s3 = "www.yahoo.com" fullword ascii
		$s4 = "MSXIML.DLL" fullword wide
		$s5 = "www.bing.com" fullword ascii
		$s6 = "%s: http://%s%s" fullword ascii
		$s7 = "/javascript/view.php" fullword ascii
		$s8 = "Task %d failed %s,%d" fullword ascii
		$s9 = "Mozilla/4.0 (compatible; MSIE %d.0; " fullword ascii

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( 1 of ( $x* ) or 6 of ( $s* ) ) ) or ( 10 of them )
}

