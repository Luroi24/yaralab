rule SIGNATURE_BASE_VULN_Dell_BIOS_Update_Driver_Dbutil_May21 : CVE_2021_21551 FILE
{
	meta:
		description = "Detects vulnerable DELL BIOS update driver that allows privilege escalation as reported in CVE-2021-21551 - DBUtil_2_3.Sys - note: it's usual location is in the C:\\Windows\\Temp folder"
		author = "Florian Roth (Nextron Systems)"
		id = "6d46866e-40fb-5fbf-b159-6bf688e638cb"
		date = "2021-05-05"
		modified = "2023-12-05"
		reference = "https://labs.sentinelone.com/cve-2021-21551-hundreds-of-millions-of-dell-computers-at-risk-due-to-multiple-bios-driver-privilege-escalation-flaws/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/vul_dell_bios_upd_driver.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "9cefb9fe28e818a3b0bc1c9ac570ddf2fac7ebf23408963656b7ec86d5bf3224"
		score = 60
		quality = 85
		tags = "CVE-2021-21551, FILE"
		hash1 = "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5"
		hash2 = "ddbf5ecca5c8086afde1fb4f551e9e6400e94f4428fe7fb5559da5cffa654cc1"

	strings:
		$s1 = "\\DBUtilDrv2" ascii
		$s2 = "DBUtil_2_3.Sys" ascii fullword
		$s3 = "[ Dell BIOS Utility Driver - " ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and all of them
}

