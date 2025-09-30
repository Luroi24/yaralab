rule VOLEXITY_Apt_Malware_Apk_Badbazaar_Common_Certificate : EVILBAMBOO FILE
{
	meta:
		description = "Detection of the common.cer file used for a large BADBAZAAR malware cluster for its certificate pinning for the C2 communication."
		author = "threatintel@volexity.com"
		id = "5a033770-7ad3-5c79-90ac-b1e3fff6b5f0"
		date = "2023-06-01"
		modified = "2023-06-13"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-09-22 EvilBamboo/indicators/rules.yar#L230-L255"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "861d4e1c40847c6ade04eddb047370d645afea6d5c16d55155fa58a16111c39e"
		score = 75
		quality = 80
		tags = "EVILBAMBOO, FILE"
		hash1 = "6aefc2b33e23f6e3c96de51d07f7123bd23ff951d67849a9bd32d446e76fb405"
		scan_context = "file"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$b1 = {30 82 03 61 30 82 02 49 a0 03 02 01 02 02 04 2b 6e df 67 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b}
		$s1 = "california1"
		$s2 = "los1"
		$s3 = "tech1"
		$s4 = "common1"
		$s5 = "common0"
		$s6 = "220401234506Z"
		$s7 = "470326234506Z0a1"

	condition:
		$b1 at 0 or all of ( $s* )
}

rule VOLEXITY_Apt_Delivery_Web_Js_Jmask_Str_Array_Variant : EVILBAMBOO FILE
{
	meta:
		description = "Detects the JMASK profiling script in an obfuscated format using a string array and an offset."
		author = "threatintel@volexity.com"
		id = "d5d32c8b-53fb-5103-ac73-05f320e71c97"
		date = "2023-06-27"
		modified = "2023-09-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-09-22 EvilBamboo/indicators/rules.yar#L408-L444"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "0ae7c96e0f866f21d66d7a23bf937d6ce48c9dd1ea19142dbb13487208780146"
		score = 75
		quality = 80
		tags = "EVILBAMBOO, FILE"
		hash1 = "7995c382263f8dbbfc37a9d62392aef8b4f89357d436b3dd94dea842f9574ecf"
		scan_context = "file"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$array_1 = "http://eular.github.io"
		$array_2 = "stun:stun.services.mozilla.com"
		$array_3 = "\xE6\x9C\xAA\xE5\xAE\x89\xE8\xA3\x85MetaMask"
		$array_4 = "/jquery/jquery.min.js"
		$array_5 = "onicecandidate"
		$ios_1 = "['a7', '640x1136', [_0x"
		$ios_2 = "['a7', _0x"
		$ios_3 = "['a8', _0x"
		$ios_4 = "['a8', '750x1334', ['iPhone\\x206']]"
		$ios_5 = "['a8', '1242x2208', ['iPhone\\x206\\x20Plus']]"
		$ios_6 = "['a8', _0x"
		$ios_7 = "['a9', _0x"
		$ios_8 = "['a9', '750x1334', [_0x"
		$ios_9 = "['a9', '1242x2208', ['iPhone\\x206s\\x20Plus']]"
		$ios_10 = "['a9x', '2048x2732', ['iPad\\x20Pro\\x20(1st\\x20gen\\x2012.9-inch)']]"
		$ios_11 = "['a10x', '1668x2224', [_0x"
		$header = "info = {}, finished = 0x0;"

	condition:
		3 of ( $array_* ) or 5 of ( $ios_* ) or $header
}

