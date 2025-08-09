rule SEKOIA_Exploit_Cve20191458_Strings : CVE_2019_1458 FILE
{
	meta:
		description = "Detects compiled exploit for CVE-2019-1458 (Generic)"
		author = "Sekoia.io"
		id = "0be4a550-0f0a-4596-ab32-aafaececf919"
		date = "2022-08-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/a47734fa931e56f8646dab2abf31629431982429/yara_rules/exploit_cve20191458_strings.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/a47734fa931e56f8646dab2abf31629431982429/LICENSE.md"
		logic_hash = "8e22a79b3d7dc45d63062c71909faee61584c71b6ea7353ba0f40c00745a2075"
		score = 75
		quality = 80
		tags = "CVE-2019-1458, FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "[-] Failed to create SploitWnd window"
		$ = "[+] ProcessCreated with pid %d!"
		$ = "[!] Exploit fail, test:0x%p,tagWND:0x%p, error:0x%lx"
		$ = "[*] tagWND: 0x%p, tagCLS:0x%p, gap:0x%llx"
		$ = "[*] Simulating alt key press"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 200KB and 3 of them
}

