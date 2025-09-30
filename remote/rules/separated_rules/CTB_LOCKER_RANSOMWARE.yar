rule TRELLIX_ARC_Backdoorfckg : CTB_LOCKER_RANSOMWARE RANSOMWARE
{
	meta:
		description = "CTB_Locker"
		author = "ISG"
		id = "2a00551d-1f80-5991-9416-d9b1b39db8e9"
		date = "2015-01-20"
		modified = "2020-08-14"
		reference = "https://blogs.mcafee.com/mcafee-labs/rise-backdoor-fckq-ctb-locker"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/ransomware/RANSOM_CTBLocker.yar#L1-L26"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "a334b07053db66aa0fb2d2b2ca7f94c480509041724ddd4dd1708052d75baffb"
		score = 75
		quality = 20
		tags = "CTB_LOCKER_RANSOMWARE, RANSOMWARE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/CTBLocker"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$string0 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		$stringl = "RNDBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		$string2 = "keme132.DLL"
		$string3 = "klospad.pdb"

	condition:
		3 of them
}

