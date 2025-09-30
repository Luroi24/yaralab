rule SEKOIA_Exploit_Linux_Eop_Cve20177308_Strings : CVE_2017_7308 FILE
{
	meta:
		description = "Detects CVE-2017-7308 exploit"
		author = "Sekoia.io"
		id = "72d225dd-386c-47d5-afb3-c6712c0bdd9a"
		date = "2023-12-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/a47734fa931e56f8646dab2abf31629431982429/yara_rules/exploit_linux_eop_cve20177308_strings.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/a47734fa931e56f8646dab2abf31629431982429/LICENSE.md"
		logic_hash = "c9fd605ced8bb2c3861f642cdc08b99b320ee19658ce60f1b9679a1ccc427bf7"
		score = 75
		quality = 80
		tags = "CVE-2017-7308, FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "[.] SMEP & SMAP bypass enabled, turning them off"
		$ = "[.] done, SMEP & SMAP should be off now"
		$ = "[.] executing get root payload %p"
		$ = "[.] done, should be root now"

	condition:
		uint32be( 0 ) == 0x7f454c46 and filesize < 1MB and all of them
}

