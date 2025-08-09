rule TRELLIX_ARC_Downloader_Darkmegi_Pdb : DOWNLOADER FILE
{
	meta:
		description = "Rule to detect DarkMegi downloader based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "3ccc3685-e05b-5620-9198-24733fb1e7eb"
		date = "2013-03-06"
		modified = "2020-08-14"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkmegi"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_downloader_darkmegi.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "bf849b1e8f170142176d2a3b4f0f34b40c16d0870833569824809b5c65b99fc1"
		logic_hash = "47faf8c5296e651f82726a6e8a7843dfa0f98e7be7257d2c03efcff550f52140"
		score = 75
		quality = 70
		tags = "DOWNLOADER, FILE"
		rule_version = "v1"
		malware_type = "downloader"
		malware_family = "Downloader:W32/DarkMegi"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\RKTDOW~1\\RKTDRI~1\\RKTDRI~1\\objchk\\i386\\RktDriver.pdb"

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 20000KB and any of them
}

rule TRELLIX_ARC_Rovnix_Downloader : DOWNLOADER
{
	meta:
		description = "Rovnix downloader with sinkhole checks"
		author = "Intel Security"
		id = "d51f8f73-7a3a-5ccf-9122-86061b5399f1"
		date = "2025-06-01"
		modified = "2020-08-14"
		reference = "https://blogs.mcafee.com/mcafee-labs/rovnix-downloader-sinkhole-time-checks/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_Rovnix.yar#L1-L38"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "52cde40c95436129b7d48b4bd5e78b66deb84fdc84a76cc9ac72f24e0777e540"
		score = 75
		quality = 43
		tags = "DOWNLOADER"
		malware_type = "downloader"
		malware_family = "Downloader:W32/Rovnix"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$sink1 = "control"
		$sink2 = "sink"
		$sink3 = "hole"
		$sink4 = "dynadot"
		$sink5 = "block"
		$sink6 = "malw"
		$sink7 = "anti"
		$sink8 = "googl"
		$sink9 = "hack"
		$sink10 = "trojan"
		$sink11 = "abuse"
		$sink12 = "virus"
		$sink13 = "black"
		$sink14 = "spam"
		$boot = "BOOTKIT_DLL.dll"
		$mz = { 4D 5A }

	condition:
		$mz in ( 0 .. 2 ) and all of ( $sink* ) and $boot
}

