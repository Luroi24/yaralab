rule SIGNATURE_BASE_EXPL_Log4J_Callbackdomain_Iocs_Dec21_1 : CVE_2021_44228
{
	meta:
		description = "Detects IOCs found in Log4Shell incidents that indicate exploitation attempts of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		id = "474afa96-1758-587e-8cab-41c5205e245e"
		date = "2021-12-12"
		modified = "2025-03-29"
		reference = "https://gist.github.com/superducktoes/9b742f7b44c71b4a0d19790228ce85d8"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_log4j_cve_2021_44228.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "8d5e60f91b715242c6f8ee806ab81d3e296ce1467cf2d065b053f33e3ae00f14"
		score = 60
		quality = 85
		tags = "CVE-2021-44228"

	strings:
		$xr1 = /\b(ldap|rmi):\/\/([a-z0-9\.]{1,16}\.bingsearchlib\.com|[a-z0-9\.]{1,40}\.interact\.sh|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):[0-9]{2,5}\/([aZ]|ua|Exploit|callback|[0-9]{10}|http443useragent|http80useragent)\b/

	condition:
		1 of them
}

rule SIGNATURE_BASE_EXPL_Log4J_CVE_2021_44228_JAVA_Exception_Dec21_1 : CVE_2021_44228
{
	meta:
		description = "Detects exceptions found in server logs that indicate an exploitation attempt of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		id = "82cf337e-4ea1-559b-a7b8-512a07adf06f"
		date = "2021-12-12"
		modified = "2025-03-29"
		reference = "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_log4j_cve_2021_44228.yar#L51-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "98eabec4ad2f5c4d22db9c3bebdc82c8dc6723599748360875fc7b613b1019ab"
		score = 60
		quality = 85
		tags = "CVE-2021-44228"

	strings:
		$xa1 = "header with value of BadAttributeValueException: "
		$sa1 = ".log4j.core.net.JndiManager.lookup(JndiManager"
		$sa2 = "Error looking up JNDI resource"

	condition:
		$xa1 or all of ( $sa* )
}

rule SIGNATURE_BASE_EXPL_Log4J_CVE_2021_44228_Dec21_Hard : FILE CVE_2021_44228
{
	meta:
		description = "Detects indicators in server logs that indicate the exploitation of CVE-2021-44228"
		author = "Florian Roth"
		id = "5297c42d-7138-507d-a3eb-153afe522816"
		date = "2021-12-10"
		modified = "2025-03-20"
		reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_log4j_cve_2021_44228.yar#L118-L140"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "9a4fc285dd1680ebc8a1042eeb5fbba73b9e2df70678adf3163122d84405325e"
		score = 65
		quality = 60
		tags = "FILE, CVE-2021-44228"

	strings:
		$x1 = /\$\{jndi:(ldap|ldaps|rmi|dns|iiop|http|nis|nds|corba):\/[\/]?[a-z-\.0-9]{3,120}:[0-9]{2,5}\/[a-zA-Z\.]{1,32}\}/
		$x2 = "Reference Class Name: foo"
		$fp1r = /(ldap|rmi|ldaps|dns):\/[\/]?(127\.0\.0\.1|192\.168\.|172\.[1-3][0-9]\.|10\.)/
		$fpg2 = "<html"
		$fpg3 = "<HTML"
		$fp1 = "/QUALYSTEST" ascii
		$fp2 = "w.nessus.org/nessus"
		$fp3 = "/nessus}"

rule SIGNATURE_BASE_SUSP_Base64_Encoded_Exploit_Indicators_Dec21 : CVE_2021_44228
{
	meta:
		description = "Detects base64 encoded strings found in payloads of exploits against log4j CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		id = "09abc4f0-ace7-5f53-b1d3-5f5c6bf3bdba"
		date = "2021-12-10"
		modified = "2021-12-13"
		reference = "https://twitter.com/Reelix/status/1469327487243071493"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_log4j_cve_2021_44228.yar#L142-L165"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "703a83916c7279bcdc3cd61602472c2a3815140235be169f5b2063a547438c61"
		score = 70
		quality = 85
		tags = "CVE-2021-44228"

	strings:
		$sa1 = "Y3VybCAtcy"
		$sa2 = "N1cmwgLXMg"
		$sa3 = "jdXJsIC1zI"
		$sb1 = "fHdnZXQgLXEgLU8tI"
		$sb2 = "x3Z2V0IC1xIC1PLS"
		$sb3 = "8d2dldCAtcSAtTy0g"
		$fp1 = "<html"

	condition:
		1 of ( $sa* ) and 1 of ( $sb* ) and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_SUSP_EXPL_OBFUSC_Dec21_1 : CVE_2021_44228 FILE
{
	meta:
		description = "Detects obfuscation methods used to evade detection in log4j exploitation attempt of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		id = "b8f56711-7922-54b9-9ce2-6ba05d64c80d"
		date = "2021-12-11"
		modified = "2022-11-08"
		reference = "https://twitter.com/testanull/status/1469549425521348609"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_log4j_cve_2021_44228.yar#L182-L211"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "d6ffb70da82fe16e7a76feb31c01aa3e0cfc5625cc0e2b237ec851c646550839"
		score = 60
		quality = 85
		tags = "CVE-2021-44228, FILE"

	strings:
		$f1 = { 24 7B 6C 6F 77 65 72 3A ?? 7D }
		$f2 = { 24 7B 75 70 70 65 72 3A ?? 7D }
		$x3 = "$%7blower:"
		$x4 = "$%7bupper:"
		$x5 = "%24%7bjndi:"
		$x6 = "$%7Blower:"
		$x7 = "$%7Bupper:"
		$x8 = "%24%7Bjndi:"
		$fp1 = "<html"

	condition:
		(1 of ( $x* ) or filesize < 200KB and 1 of ( $f* ) ) and not 1 of ( $fp* )
}

