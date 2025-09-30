rule SBOUSSEADEN_Hunt_Teamviewer_Registry_Pwddump : CVE_2019_18988 FILE
{
	meta:
		description = "cve-2019-18988 - decryption of AES 128 bits encrypted TV config pwds saved in TV registry hive"
		author = "SBousseaden"
		id = "b2240cda-a37a-572e-b915-be39cbaabaaf"
		date = "2020-07-23"
		modified = "2020-12-28"
		reference = "https://community.teamviewer.com/t5/Announcements/Specification-on-CVE-2019-18988/td-p/82264"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_capab_credentials_access.yara#L266-L286"
		license_url = "N/A"
		logic_hash = "a0cb06e06904e98e963798fddc28e2a7cf8b737a50ff7d380e7f871c78ed9479"
		score = 50
		quality = 63
		tags = "CVE-2019-18988, FILE"

	strings:
		$key1 = {0602000000a400005253413100040000}
		$key2 = "\\x06\\x02\\x00\\x00\\x00\\xa4\\x00\\x00\\x52\\x53\\x41\\x31\\x00\\x04\\x00\\x00"
		$iv1 = {0100010067244F436E6762F25EA8D704}
		$iv2 = "\\x01\\x00\\x01\\x00\\x67\\x24\\x4F\\x43\\x6E\\x67\\x62\\xF2\\x5E\\xA8\\xD7\\x04"
		$p1 = "OptionsPasswordAES" nocase
		$p2 = "OptionsPasswordAES" nocase wide
		$p3 = "ProxyPasswordAES" nocase
		$p4 = "ProxyPasswordAES" nocase wide
		$p5 = "PermanentPassword" nocase
		$p6 = "PermanentPassword" nocase wide

	condition:
		any of ( $key* ) and any of ( $iv* ) and 2 of ( $p* ) and filesize < 700KB
}

