rule TELEKOM_SECURITY_Vatet_Loader_Rufus_Backdoor : DEFRAY777
{
	meta:
		description = "Detects backdoored Rufus with Vatet Loader of Defray777"
		author = "Thomas Barabosch, Deutsche Telekom Security"
		id = "1f6fa228-300c-59de-b89c-3cbdce1b6374"
		date = "2022-03-18"
		modified = "2022-03-18"
		reference = "https://unit42.paloaltonetworks.com/vatet-pyxie-defray777"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/defray777/vatet_loader.yar#L1-L27"
		license_url = "N/A"
		logic_hash = "3767398112759689078f992eb272cfec3e59f6d9ca30f8da68c2053e1217fd18"
		score = 75
		quality = 20
		tags = "DEFRAY777"
		sharing = "TLP:WHITE"
		hash_1 = "c9c1caae50459896a15dce30eaca91e49e875207054d98e32e16a3e203446569"
		hash_2 = "0cb8fc89541969304f3bf806e938452b36348bdd0280fc8f4e9221993e745334"
		in_memory = "False"

	strings:
		$payload_decryption = { 66 0F F8 C1 66 0F EF C2 66 0F F8 C1 }
		$mz = "MZ" ascii
		$rufus = "https://rufus.ie/" ascii

	condition:
		$mz at 0 and $payload_decryption and $rufus
}

