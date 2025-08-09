rule SIGNATURE_BASE_Flash_CVE_2015_5119_APT3_Leg : CVE_2015_5119 FILE
{
	meta:
		description = "Exploit Sample CVE-2015-5119"
		author = "Florian Roth (Nextron Systems)"
		id = "d9efaea3-0644-501a-990b-665e257beb86"
		date = "2015-08-01"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2015_5119.yar#L2-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "99af6b9ecc18b87b14968eb8fffefac7be10dd727d8af2d0488fae4a96196e85"
		score = 70
		quality = 85
		tags = "CVE-2015-5119, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		yaraexchange = "No distribution without author's consent"

	strings:
		$s0 = "HT_exploit" fullword ascii
		$s1 = "HT_Exploit" fullword ascii
		$s2 = "flash_exploit_" ascii
		$s3 = "exp1_fla/MainTimeline" ascii fullword
		$s4 = "exp2_fla/MainTimeline" ascii fullword
		$s5 = "_shellcode_32" ascii
		$s6 = "todo: unknown 32-bit target" fullword ascii

	condition:
		uint16( 0 ) == 0x5746 and 1 of them
}

