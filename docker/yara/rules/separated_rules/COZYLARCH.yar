rule VOLEXITY_Apt_Malware_Win_Flipflop_Ldr : COZYLARCH FILE MEMORY
{
	meta:
		description = "A loader for the CobaltStrike malware family, which ultimately takes the first and second bytes of an embedded file, and flips them prior to executing the resulting payload."
		author = "threatintel@volexity.com"
		id = "58696a6f-55a9-5212-9372-a539cc327e6b"
		date = "2021-05-25"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-05-27 - Suspected APT29 Operation Launches Election Fraud Themed Phishing Campaigns/indicators/yara.yar#L3-L26"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
		logic_hash = "a79d2b0700ae14f7a2af23c8f7df3df3564402b1137478008ccabefea0f543ad"
		score = 75
		quality = 80
		tags = "COZYLARCH, FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5443
		version = 6

	strings:
		$s1 = "irnjadle"
		$s2 = "BADCFEHGJILKNMPORQTSVUXWZY"
		$s3 = "iMrcsofo taBesC yrtpgoarhpciP orived r1v0."

	condition:
		all of ( $s* )
}

rule VOLEXITY_Apt_Malware_Win_Freshfire : COZYLARCH FILE
{
	meta:
		description = "The FRESHFIRE malware family. The malware acts as a downloader, pulling down an encrypted snippet of code from a remote source, executing it, and deleting it from the remote server."
		author = "threatintel@volexity.com"
		id = "050b8e61-139a-5ff5-998a-7de67c9975bf"
		date = "2021-05-27"
		modified = "2025-05-21"
		reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-05-27 - Suspected APT29 Operation Launches Election Fraud Themed Phishing Campaigns/indicators/yara.yar#L55-L87"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "ad67aaa50fd60d02f1378b4155f69cffa9591eaeb80523489a2355512cc30e8c"
		logic_hash = "69cd73f5812ba955c1352fb1552774d5cf49019d6b65a304fd1e33f852e678ba"
		score = 75
		quality = 80
		tags = "COZYLARCH, FILE"
		os = "win"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5459
		version = 9

	strings:
		$uniq1 = "UlswcXJJWhtHIHrVqWJJ"
		$uniq2 = "gyibvmt\x00"
		$path1 = "root/time/%d/%s.json"
		$path2 = "C:\\dell.sdr"
		$path3 = "root/data/%d/%s.json"

	condition:
		(pe.number_of_exports == 1 and pe.exports ( "WaitPrompt" ) ) or any of ( $uniq* ) or 2 of ( $path* )
}

