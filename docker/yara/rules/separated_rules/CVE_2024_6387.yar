rule CRAIU_Exploit_CVE_2024_6387 : CVE_2024_6387 FILE
{
	meta:
		description = "Strings from CVE-2024-6387 exploit PoC by zgzhang."
		author = "Costin G. Raiu, TLPBLACK, craiu@noh.ro"
		id = "6ac63016-864d-57af-bb36-3115a0a91021"
		date = "2024-07-02"
		modified = "2024-07-03"
		reference = "https://github.com/zgzhang/cve-2024-6387-poc/tree/main"
		source_url = "https://github.com/craiu/yararules/blob/23cf0ca22021fa3684e180a18416b9ae1b695243/files/exploit_cve_2024_6387.yara#L2-L38"
		license_url = "https://github.com/craiu/yararules/blob/23cf0ca22021fa3684e180a18416b9ae1b695243/LICENSE"
		hash = "62b06a6c30a0c891c2246ff87c0ad9ae03d2123601ba5331d6348c43b38d185e"
		logic_hash = "d43a77c2690b5e01639590bc31fa64fa36b1da5efd3cc0761be7369ce80e4253"
		score = 75
		quality = 85
		tags = "CVE-2024-6387, FILE"
		version = "1.0"

	strings:
		$a0 = "Attempting exploitation with glibc base: 0x%lx" ascii wide fullword
		$a1 = "Attempt %d of 20000" ascii wide fullword
		$a2 = "Failed to establish connection, attempt %d" ascii wide fullword
		$a3 = "SSH handshake failed, attempt %d" ascii wide fullword
		$a4 = "Possible exploitation success on attempt %d with glibc base 0x%lx!" ascii wide fullword
		$a5 = "Received SSH version: %s" ascii wide fullword
		$a6 = "Connection closed while receiving SSH version" ascii wide fullword
		$a7 = "Received KEX_INIT (%zd bytes)" ascii wide fullword
		$a8 = "Connection closed while receiving KEX_INIT" ascii wide fullword
		$a9 = "Estimated parsing time: %.6f seconds" ascii wide fullword
		$a10 = "Received response after exploit attempt (%zd bytes)" ascii wide fullword
		$a11 = "Possible hit on 'large' race window" ascii wide fullword
		$a12 = "Connection closed by server - possible successful exploitation" ascii wide fullword
		$a13 = "No immediate response from server - possible successful exploitation" ascii wide fullword
		$a14 = "Attempt %d of 10000" ascii wide fullword

	condition:
		( filesize < 5MB ) and ( uint32be( 0 ) == 0x7F454C46 ) and ( 4 of ( $a* ) )
}

