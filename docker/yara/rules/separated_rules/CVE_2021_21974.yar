rule SEKOIA_Exploit_Linux_Eop_Cve202121974_Exploit_Strings : CVE_2021_21974 FILE
{
	meta:
		description = "Detects CVE-2021-21974 Local Privesc exploit"
		author = "Sekoia.io"
		id = "8e1fbbe5-7d51-48b4-80d5-90abff8cab9e"
		date = "2023-12-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/a47734fa931e56f8646dab2abf31629431982429/yara_rules/exploit_linux_eop_cve202121974_exploit_strings.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/a47734fa931e56f8646dab2abf31629431982429/LICENSE.md"
		logic_hash = "a2e6e2660fcbf6ffa80809c02ca78fae85d27f6cd8d2c83bb2645a86124ca7f2"
		score = 75
		quality = 80
		tags = "CVE-2021-21974, FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = ".name.replace('Thread','SLP Client'"
		$ = "print('[' + name + '] recv: ', d)"
		$ = "requests[28].put(connect())"
		$ = "[+] stack enviorn address:"

	condition:
		uint32be( 0 ) == 0x7f454c46 and filesize < 1MB and all of them
}

