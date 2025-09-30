rule SIGNATURE_BASE_CVE_2015_1674_CNGSYS : CVE_2015_1674 FILE
{
	meta:
		description = "Detects exploits for CVE-2015-1674"
		author = "Florian Roth (Nextron Systems)"
		id = "1161b395-a19e-5aac-8416-8a4e60aeca37"
		date = "2015-05-14"
		modified = "2023-12-05"
		reference = "http://www.binvul.com/viewthread.php?tid=508"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2015_1674.yar#L10-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "af4eb2a275f6bbc2bfeef656642ede9ce04fad36"
		logic_hash = "d751ef739a6fb8b0871f92cb4aba21544f444944710407c723f0452dc3b85522"
		score = 75
		quality = 85
		tags = "CVE-2015-1674, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\Device\\CNG" wide
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "LoadLibrary" ascii
		$s4 = "KERNEL32.dll" fullword ascii
		$s5 = "ntdll.dll" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 60KB and all of them
}

