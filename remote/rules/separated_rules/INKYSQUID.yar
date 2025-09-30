rule SIGNATURE_BASE_APT_MAL_Win_Bluelight_B : INKYSQUID
{
	meta:
		description = "North Korean origin malware which uses a custom Google App for c2 communications."
		author = "threatintel@volexity.com"
		id = "3ec2d44c-4c08-514d-a839-acef3f53f7dc"
		date = "2021-06-21"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/08/17/north-korean-apt-inkysquid-infects-victims-using-browser-exploits/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_apt37_bluelight.yar#L12-L112"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "a6e83ca2ae15f1a7819f065449f84166da401739d091565605d62ebba3d47a50"
		score = 75
		quality = 60
		tags = "INKYSQUID"
		hash1 = "837eaf7b736583497afb8bbdb527f70577901eff04cc69d807983b233524bfed"
		license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"

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
		$keylogger_component1 = "[TAB]"
		$keylogger_component2 = "[RETURN]"
		$keylogger_component3 = "PAUSE"
		$keylogger_component4 = "[ESC]"
		$keylogger_component5 = "[PAGE UP]"
		$keylogger_component6 = "[PAGE DOWN]"
		$keylogger_component7 = "[END]"
		$keylogger_component8 = "[HOME]"
		$keylogger_component9 = "[ARROW LEFT]"
		$keylogger_component10 = "[ARROW UP]"
		$keylogger_component11 = "[ARROW RIGHT]"
		$keylogger_component12 = "[ARROW DOWN]"
		$keylogger_component13 = "[INS]"
		$keylogger_component14 = "[DEL]"
		$keylogger_component15 = "[WIN]"
		$keylogger_component16 = "[NUM *]"
		$keylogger_component17 = "[NUM +]"
		$keylogger_component18 = "[NUM ,]"
		$keylogger_component19 = "[NUM -]"
		$keylogger_component20 = "[NUM .]"
		$keylogger_component21 = "NUM /]"
		$keylogger_component22 = "[NUMLOCK]"
		$keylogger_component23 = "[SCROLLLOCK]"
		$keylogger_component24 = "Time: "
		$keylogger_component25 = "Window: "
		$keylogger_component26 = "CAPSLOCK+"
		$keylogger_component27 = "SHIFT+"
		$keylogger_component28 = "CTRL+"
		$keylogger_component29 = "ALT+"

	condition:
		$magic or ( all of ( $f* ) and 5 of ( $keylogger_component* ) ) or 24 of ( $chrome* ) or 4 of ( $msg* ) or 27 of ( $keylogger_component* )
}

rule SIGNATURE_BASE_APT_MAL_Win_Bluelight : INKYSQUID
{
	meta:
		description = "The BLUELIGHT malware family. Leverages Microsoft OneDrive for network communications."
		author = "threatintel@volexity.com"
		id = "3ec2d44c-4c08-514d-a839-acef3f53f7dc"
		date = "2021-04-23"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/08/17/north-korean-apt-inkysquid-infects-victims-using-browser-exploits/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_apt37_bluelight.yar#L114-L144"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "52589348f42aadbe453ad8a40ac36b58fcc9e07cd298486f09b6f793823d8cc7"
		score = 75
		quality = 85
		tags = "INKYSQUID"
		hash1 = "7c40019c1d4cef2ffdd1dd8f388aaba537440b1bffee41789c900122d075a86d"
		hash2 = "94b71ee0861cc7cfbbae53ad2e411a76f296fd5684edf6b25ebe79bf6a2a600a"
		license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"

	strings:
		$pdb1 = "\\Development\\BACKDOOR\\ncov\\"
		$pdb2 = "Release\\bluelight.pdb"
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

rule SIGNATURE_BASE_APT_PY_Bluelight_Loader : INKYSQUID
{
	meta:
		description = "Python Loader used to execute the BLUELIGHT malware family."
		author = "threatintel@volexity.com"
		id = "f8da3e40-c3b0-5b7f-8ece-81874993d8cd"
		date = "2021-06-22"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_nk_inkysquid.yar#L39-L58"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "e7e18a6d648b1383706439ba923335ac4396f6b5d2a3dc8f30f63ded7df29eda"
		score = 75
		quality = 85
		tags = "INKYSQUID"
		hash1 = "80269413be6ad51b8b19631b2f5559c9572842e789bbce031babe6e879d2e120"
		license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"

	strings:
		$s1 = "\"\".join(chr(ord(" ascii
		$s2 = "import ctypes " ascii
		$s3 = "ctypes.CFUNCTYPE(ctypes.c_int)" ascii
		$s4 = "ctypes.memmove" ascii
		$s5 = "python ended" ascii

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_Win_Decrok : INKYSQUID
{
	meta:
		description = "The DECROK malware family, which uses the victim's hostname to decrypt and execute an embedded payload."
		author = "threatintel@volexity.com"
		id = "dc83843d-fd2a-52f1-82e8-8e36b135a0c5"
		date = "2021-06-23"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_nk_inkysquid.yar#L61-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "6a452d088d60113f623b852f33f8f9acf0d4197af29781f889613fed38f57855"
		logic_hash = "47fa03e95ac17ba7195858cd63b1769e5d56ab8a5edf872b345989b767050b87"
		score = 75
		quality = 85
		tags = "INKYSQUID"
		license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"

	strings:
		$v1 = {C7 ?? ?? ?? 01 23 45 67 [2-20] C7 ?? ?? ?? 89 AB CD EF C7 ?? ?? ?? FE DC BA 98}
		$av1 = "Select * From AntiVirusProduct" wide
		$av2 = "root\\SecurityCenter2" wide
		$funcformat = { 25 30 32 78 [0-10] 43 72 65 61 74 65 54 68 72 65 61 64 }

	condition:
		all of them
}

