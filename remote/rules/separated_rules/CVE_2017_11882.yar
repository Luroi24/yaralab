rule SIGNATURE_BASE_Rtf_Cve2017_11882_Ole : MALICIOUS EXPLOIT CVE_2017_11882
{
	meta:
		description = "Attempts to identify the exploit CVE 2017 11882"
		author = "John Davison"
		id = "b6c59cf1-52e4-5c9e-b3c3-d973d52736e3"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2017_11882.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "51cf2a6c0c1a29abca9fd13cb22421da"
		logic_hash = "6856d3c78cc06899d2bc1f876dce6b718513ebad80f37d7b5914a14d1da5064c"
		score = 60
		quality = 85
		tags = "MALICIOUS, EXPLOIT, CVE_2017_11882"

	strings:
		$headers = { 1c 00 00 00 02 00 ?? ?? a9 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 01 01 03 ?? }
		$font = { 0a 01 08 5a 5a }
		$winexec = { 12 0c 43 00 }

	condition:
		all of them and @font > @headers and @winexec == @font + 5 + 44
}

rule SIGNATURE_BASE_Packager_Cve2017_11882 : CVE_2017_11882 FILE
{
	meta:
		description = "Attempts to exploit CVE-2017-11882 using Packager"
		author = "Rich Warren"
		id = "57ff395e-e56a-5e63-bde6-f3cef038fcd6"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/rxwx/CVE-2017-11882/blob/master/packager_exec_CVE-2017-11882.py"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2017_11882.yar#L41-L56"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "94e0c70e8140bb7fa3d184447617b534a8b9a24cdad535e6818be9662f0b9144"
		score = 60
		quality = 54
		tags = "CVE-2017-11882, FILE"

	strings:
		$font = { 30 61 30 31 30 38 35 61  35 61 }
		$equation = { 45 71 75 61 74 69 6F 6E 2E 33 }
		$package = { 50 61 63 6b 61 67 65 }
		$header_and_shellcode = /03010[0,1][0-9a-fA-F]{108}00/ ascii nocase

	condition:
		uint32be( 0 ) == 0x7B5C7274 and all of them
}

rule SIGNATURE_BASE_CVE_2017_11882_RTF : CVE_2017_11882 FILE
{
	meta:
		description = "Detects suspicious Microsoft Equation OLE contents as used in CVE-2017-11882"
		author = "Florian Roth (Nextron Systems)"
		id = "400689ff-e856-5cbf-a7fa-93f6a8d8dbb9"
		date = "2018-02-13"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2017_11882.yar#L58-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "729fa8215a24990371369158d4582cc0ba9387eb0e7221860bf7216046c447cb"
		score = 60
		quality = 85
		tags = "CVE-2017-11882, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "4d534854412e4558452068747470"
		$x2 = "6d736874612e6578652068747470"
		$x3 = "6d736874612068747470"
		$x4 = "4d534854412068747470"
		$s1 = "4d6963726f736f6674204571756174696f6e20332e30" ascii
		$s2 = "4500710075006100740069006f006e0020004e00610074006900760065" ascii
		$s3 = "2e687461000000000000000000000000000000000000000000000"

	condition:
		( uint32be( 0 ) == 0x7B5C7274 or uint32be( 0 ) == 0x7B5C2A5C ) and filesize < 300KB and ( 1 of ( $x* ) or 2 of them )
}

