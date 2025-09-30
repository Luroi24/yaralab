rule TRELLIX_ARC_Apt_Hikit_Rootkit : ROOTKIT FILE
{
	meta:
		description = "Rule to detect the rootkit hikit based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "c53acbc6-8f4a-590b-8dd7-ce4da6d79cf8"
		date = "2012-08-20"
		modified = "2020-08-14"
		reference = "https://www.fireeye.com/blog/threat-research/2012/08/hikit-rootkit-advanced-persistent-attack-techniques-part-1.html"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_hikit_rootkit_pdb.yar#L1-L28"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "8a425ababdfbe95bd8ac7d4f519be16c0f1fd0b7eea2874124db2f00dd6eb56d"
		score = 75
		quality = 70
		tags = "ROOTKIT, FILE"
		rule_version = "v1"
		malware_type = "rootkit"
		malware_family = "Rootkit:W32/Hikit"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\JmVodServer\\hikit\\bin32\\RServer.pdb"
		$pdb1 = "\\JmVodServer\\hikit\\bin32\\w7fw.pdb"
		$pdb2 = "\\JmVodServer\\hikit\\bin32\\w7fw_2k.pdb"
		$pdb3 = "\\JmVodServer\\hikit\\bin64\\w7fw_x64.pdb"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and any of them
}

