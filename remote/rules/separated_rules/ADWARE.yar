rule TRELLIX_ARC_Malw_Browser_Fox_Adware : ADWARE FILE
{
	meta:
		description = "Rule to detect Browser Fox Adware based on the PDB reference"
		author = "Marc Rivero | McAfee ATR Team"
		id = "67d20c3a-4e9d-5fbf-b26a-d7b5fb270d12"
		date = "2015-01-15"
		modified = "2020-08-14"
		reference = "https://www.sophos.com/en-us/threat-center/threat-analyses/adware-and-puas/Browse%20Fox.aspx"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_browser_fox_adware.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "c6f3d6024339940896dd18f32064c0773d51f0261ecbee8b0534fdd9a149ac64"
		logic_hash = "462a05de46ec0d710cac80a05d4935279a43f49cbd5ef49c072f277982a76fce"
		score = 75
		quality = 70
		tags = "ADWARE, FILE"
		rule_version = "v1"
		malware_type = "adware"
		malware_family = "Adware:W32/BrowserFox"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Utilities\\130ijkfv.o4g\\Desktop\\Desktop.OptChecker\\bin\\Release\\ BooZaka.Opt"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and any of them
}

