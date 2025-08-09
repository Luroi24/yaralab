rule VOLEXITY_Apt_Malware_Rb_Rokrat_Loader : INKYPINE FILE MEMORY
{
	meta:
		description = "Ruby loader seen loading the ROKRAT malware family."
		author = "threatintel@volexity.com"
		id = "69d09560-a769-55d3-a442-e37f10453cde"
		date = "2021-06-22"
		modified = "2024-08-22"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L1-L32"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "30ae14fd55a3ab60e791064f69377f3b9de9b871adfd055f435df657f89f8007"
		score = 75
		quality = 55
		tags = "INKYPINE, FILE, MEMORY"
		hash1 = "5bc52f6c1c0d0131cee30b4f192ce738ad70bcb56e84180f464a5125d1a784b2"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5598
		version = 7

	strings:
		$magic1 = "'https://update.microsoft.com/driverupdate?id=" ascii wide
		$magic2 = "sVHZv1mCNYDO0AzI';" ascii wide
		$magic3 = "firoffset..scupd.size" ascii wide
		$magic4 = /alias UrlFilter[0-9]{2,5} eval;"/
		$s1 = "clRnbp9GU6oTZsRGZpZ"
		$s2 = "RmlkZGxlOjpQb2ludGVy"
		$s3 = "yVGdul2bQpjOlxGZklmR"
		$s4 = "XZ05WavBlO6UGbkRWaG"

	condition:
		any of ( $magic* ) or any of ( $s* )
}

rule VOLEXITY_Apt_Malware_Py_Bluelight_Ldr : INKYPINE FILE
{
	meta:
		description = "Python Loader used to execute the BLUELIGHT malware family."
		author = "threatintel@volexity.com"
		id = "db32b752-eba4-52a6-80b6-d1d394660453"
		date = "2021-06-22"
		modified = "2025-02-18"
		reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L33-L61"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "6987f5903561da8d4fa32c8d824593f601a49e13edfa2d617952d57ba3444f76"
		score = 75
		quality = 80
		tags = "INKYPINE, FILE"
		hash1 = "80269413be6ad51b8b19631b2f5559c9572842e789bbce031babe6e879d2e120"
		os = "win"
		os_arch = "all"
		scan_context = "file"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5600
		version = 6

	strings:
		$s1 = "\"\".join(chr(ord(" ascii
		$s2 = "import ctypes" ascii
		$s3 = "ctypes.CFUNCTYPE(ctypes.c_int)" ascii
		$s4 = "ctypes.memmove" ascii
		$magic = "writelines(\"python ended\")" ascii

	condition:
		all of ( $s* ) or $magic
}

rule VOLEXITY_Apt_Malware_Win_Decrok : INKYPINE FILE MEMORY
{
	meta:
		description = "The DECROK malware family, which uses the victim's hostname to decrypt and execute an embedded payload."
		author = "threatintel@volexity.com"
		id = "46be1793-6419-54fe-a78b-5d087e02626e"
		date = "2021-06-23"
		modified = "2023-09-28"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L62-L90"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "6a452d088d60113f623b852f33f8f9acf0d4197af29781f889613fed38f57855"
		logic_hash = "a551700943d5abc95af00fc4fefd416ace8d59037852c6bc5caf1d6bd09afd63"
		score = 75
		quality = 80
		tags = "INKYPINE, FILE, MEMORY"
		os = "win"
		os_arch = "x86"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5606
		version = 4

	strings:
		$v1 = {C7 ?? ?? ?? 01 23 45 67 [2-20] C7 ?? ?? ?? 89 AB CD EF C7 ?? ?? ?? FE DC BA 98}
		$av1 = "Select * From AntiVirusProduct" wide
		$av2 = "root\\SecurityCenter2" wide
		$func1 = "CreateThread"
		$format = "%02x"

	condition:
		all of them and $func1 in ( @format .. @format + 10 )
}

rule VOLEXITY_Apt_Malware_Win_Rokload : INKYPINE FILE
{
	meta:
		description = "A shellcode loader used to decrypt and run an embedded executable."
		author = "threatintel@volexity.com"
		id = "229dbf3c-1538-5ecd-b5f8-8c9a9c81c515"
		date = "2021-06-23"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L91-L112"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "85cd5c3bb028fe6931130ccd5d0b0c535c01ce2bcda660a3b72581a1a5382904"
		logic_hash = "8d65d32fd5bc055ca0e3831d3db88299e7c99f8547a170d3c53ec2c4001496a3"
		score = 75
		quality = 80
		tags = "INKYPINE, FILE"
		os = "win"
		os_arch = "x64"
		scan_context = "file"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5603
		version = 4

	strings:
		$bytes00 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 57 41 54 41 55 41 56 41 57 48 ?? ?? ?? b9 ?? ?? ?? ?? 33 ff e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 4c 8b e8 e8 ?? ?? ?? ?? 4c 8b f0 41 ff d6 b9 ?? ?? ?? ?? 44 8b f8 e8 ?? ?? ?? ?? 4c 8b e0 e8 ?? ?? ?? ?? 48 }

	condition:
		$bytes00 at 0
}

rule VOLEXITY_Apt_Malware_Win_Dolphin : INKYPINE FILE MEMORY
{
	meta:
		description = "North Korean origin malware which uses a custom Google App for c2 communications."
		author = "threatintel@volexity.com"
		id = "27bb2b41-f77d-5b95-b555-206c39ed9e6c"
		date = "2021-06-21"
		modified = "2025-01-27"
		reference = "https://www.welivesecurity.com/2022/11/30/whos-swimming-south-korean-waters-meet-scarcrufts-dolphin/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-17 - InkySquid Part 1/indicators/yara.yar#L1-L77"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "785a92087efc816c88c6eed6363c432d8d45198fbd5cef84c04dabd36b6316a6"
		score = 75
		quality = 55
		tags = "INKYPINE, FILE, MEMORY"
		hash1 = "837eaf7b736583497afb8bbdb527f70577901eff04cc69d807983b233524bfed"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5593
		version = 10

	strings:
		$magic = "host_name: %ls, cookie_name: %s, cookie: %s, CT: %llu, ET: %llu, value: %s, path: %ls, secu: %d, http: %d, last: %llu, has: %d"
		$f1 = "%ls.INTEG.RAW" wide
		$f2 = "edb.chk" ascii
		$f3 = "edb.log" ascii
		$f4 = "edbres00001.jrs" ascii
		$f5 = "edbres00002.jrs" ascii
		$f6 = "edbtmp.log" ascii
		$f7 = "cheV01.dat" ascii
		$chrome1 = "Failed to get chrome cookie"
		$chrome2 = "mail.google.com, cookie_name: OSID"
		$chrome3 = ".google.com, cookie_name: SID,"
		$chrome4 = ".google.com, cookie_name: __Secure-3PSID,"
		$chrome5 = "Failed to get Edge cookie"
		$chrome6 = "google.com, cookie_name: SID,"
		$chrome7 = "google.com, cookie_name: __Secure-3PSID,"
		$chrome8 = "Failed to get New Edge cookie"
		$chrome9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0"
		$chrome10 = "Content-Type: application/x-www-form-urlencoded;charset=utf-8"
		$chrome11 = "Cookie: SID=%s; OSID=%s; __Secure-3PSID=%s"
		$chrome12 = "https://mail.google.com"
		$chrome13 = "result.html"
		$chrome14 = "GM_ACTION_TOKEN"
		$chrome15 = "GM_ID_KEY="
		$chrome16 = "/mail/u/0/?ik=%s&at=%s&view=up&act=prefs"
		$chrome17 = "p_bx_ie=1"
		$chrome18 = "myaccount.google.com, cookie_name: OSID"
		$chrome19 = "Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3"
		$chrome20 = "Content-Type: application/x-www-form-urlencoded;charset=utf-8"
		$chrome21 = "Cookie: SID=%s; OSID=%s; __Secure-3PSID=%s"
		$chrome22 = "https://myaccount.google.com"
		$chrome23 = "result.html"
		$chrome24 = "myaccount.google.com"
		$chrome25 = "/_/AccountSettingsUi/data/batchexecute"
		$chrome26 = "f.req=%5B%5B%5B%22BqLdsd%22%2C%22%5Btrue%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at="
		$chrome27 = "response.html"
		$msg1 = "https_status is %s"
		$msg2 = "Success to find GM_ACTION_TOKEN and GM_ID_KEY"
		$msg3 = "Failed to find GM_ACTION_TOKEN and GM_ID_KEY"
		$msg4 = "Failed HttpSendRequest to mail.google.com"
		$msg5 = "Success to enable imap"
		$msg6 = "Failed to enable imap"
		$msg7 = "Success to find SNlM0e"
		$msg8 = "Failed to find SNlM0e"
		$msg9 = "Failed HttpSendRequest to myaccount.google.com"
		$msg10 = "Success to enable thunder access"
		$msg11 = "Failed to enable thunder access"

	condition:
		$magic or ( all of ( $f* ) and 3 of ( $chrome* ) ) or 24 of ( $chrome* ) or 4 of ( $msg* )
}

rule VOLEXITY_Apt_Malware_Win_Bluelight : INKYPINE FILE MEMORY
{
	meta:
		description = "The BLUELIGHT malware family. Leverages Microsoft OneDrive for network communications."
		author = "threatintel@volexity.com"
		id = "5bfdc74b-592e-5f3d-9fb8-bbbbd0f6f0f6"
		date = "2021-04-23"
		modified = "2025-02-18"
		reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-17 - InkySquid Part 1/indicators/yara.yar#L78-L120"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "45490dfc793bb95f153c0194989b25e0b2641fa9b9f6763d5733eab6483ffead"
		score = 75
		quality = 80
		tags = "INKYPINE, FILE, MEMORY"
		hash1 = "7c40019c1d4cef2ffdd1dd8f388aaba537440b1bffee41789c900122d075a86d"
		hash2 = "94b71ee0861cc7cfbbae53ad2e411a76f296fd5684edf6b25ebe79bf6a2a600a"
		hash3 = "485246b411ef5ea9e903397a5490d106946a8323aaf79e6041bdf94763a0c028"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5284
		version = 12

	strings:
		$pdb1 = "\\Development\\BACKDOOR\\ncov\\"
		$pdb2 = "Release\\bluelight.pdb" nocase ascii
		$pdb3 = "D:\\Development\\GOLD-BACKDOOR\\Release\\FirstBackdoor.pdb"
		$pdb4 = "GOLD-BACKDOOR\\Release\\"
		$msg0 = "https://ipinfo.io" fullword
		$msg1 = "country" fullword
		$msg5 = "\"UserName\":\"" fullword
		$msg7 = "\"ComName\":\"" fullword
		$msg8 = "\"OS\":\"" fullword
		$msg9 = "\"OnlineIP\":\"" fullword
		$msg10 = "\"LocalIP\":\"" fullword
		$msg11 = "\"Time\":\"" fullword
		$msg12 = "\"Compiled\":\"" fullword
		$msg13 = "\"Process Level\":\"" fullword
		$msg14 = "\"AntiVirus\":\"" fullword
		$msg15 = "\"VM\":\"" fullword

	condition:
		any of ( $pdb* ) or all of ( $msg* )
}

