rule SIGNATURE_BASE_APT_UNC4841_ESG_Barracuda_CVE_2023_2868_Forensic_Artifacts_Jun23_1 : SCRIPT CVE_2023_2868
{
	meta:
		description = "Detects forensic artifacts found in the exploitation of CVE-2023-2868 in Barracuda ESG devices by UNC4841"
		author = "Florian Roth"
		id = "50518fa1-33de-5fe5-b957-904d976fb29a"
		date = "2023-06-15"
		modified = "2023-06-16"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_barracuda_esg_unc4841_jun23.yar#L2-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "fa7cac1e0f6cb6fa3ac271c1fff0039ff182b6859920b4eca25541457654acde"
		score = 75
		quality = 85
		tags = "SCRIPT, CVE-2023-2868"

	strings:
		$x01 = "=;ee=ba;G=s;_ech_o $abcdefg_${ee}se64" ascii
		$x02 = ";echo $abcdefg | base64 -d | sh" ascii
		$x03 = "setsid sh -c \"mkfifo /tmp/p" ascii
		$x04 = "sh -i </tmp/p 2>&1" ascii
		$x05 = "if string.match(hdr:body(), \"^[%w%+/=" ascii
		$x06 = "setsid sh -c \"/sbin/BarracudaMailService eth0\""
		$x07 = "echo \"set the bvp ok\""
		$x08 = "find ${path} -type f ! -name $excludeFileNameKeyword | while read line ;"
		$x09 = " /mail/mstore | xargs -i cp {} /usr/share/.uc/"
		$x10 = "tar -T /mail/mstore/tmplist -czvf "
		$sa1 = "sh -c wget --no-check-certificate http"
		$sa2 = ".tar;chmod +x "

	condition:
		1 of ( $x* ) or all of ( $sa* )
}

rule SIGNATURE_BASE_APT_MAL_UNC4841_SEASPY_Jun23_1 : CVE_2023_2868 FILE
{
	meta:
		description = "Detects SEASPY malware used by UNC4841 in attacks against Barracuda ESG appliances exploiting CVE-2023-2868"
		author = "Florian Roth"
		id = "bcff58f8-87f6-5371-8b96-5d4c0f349000"
		date = "2023-06-16"
		modified = "2023-12-05"
		reference = "https://blog.talosintelligence.com/alchimist-offensive-framework/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_barracuda_esg_unc4841_jun23.yar#L30-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "c1dcb841fb872f0d5e661bfd90fca3075f5efc95b1f9dfff72fa318ed131e9d1"
		score = 85
		quality = 85
		tags = "CVE-2023-2868, FILE"
		hash1 = "3f26a13f023ad0dcd7f2aa4e7771bba74910ee227b4b36ff72edc5f07336f115"

	strings:
		$sx1 = "usage: ./BarracudaMailService <Network-Interface>. e.g.: ./BarracudaMailService eth0" ascii fullword
		$s1 = "fcntl.tmp.amd64." ascii
		$s2 = "Child process id:%d" ascii fullword
		$s3 = "[*]Success!" ascii fullword
		$s4 = "NO port code" ascii
		$s5 = "enter open tty shell" ascii
		$op1 = { 48 89 c6 f3 a6 0f 84 f7 01 00 00 bf 6c 84 5f 00 b9 05 00 00 00 48 89 c6 f3 a6 0f 84 6a 01 00 00 }
		$op2 = { f3 a6 0f 84 d2 00 00 00 48 89 de bf 51 5e 61 00 b9 05 00 00 00 f3 a6 74 21 48 89 de }
		$op3 = { 72 de 45 89 f4 e9 b8 f4 ff ff 48 8b 73 08 45 85 e4 ba 49 3d 62 00 b8 44 81 62 00 48 0f 45 d0 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 9000KB and 3 of them or 5 of them
}

rule SIGNATURE_BASE_MAL_ELF_Reverseshell_Sslshell_Jun23_1 : CVE_2023_2868 FILE
{
	meta:
		description = "Detects reverse shell named SSLShell used in Barracuda ESG exploitation (CVE-2023-2868)"
		author = "Florian Roth"
		id = "91b34eb7-61d2-592e-a444-249da43994ca"
		date = "2023-06-07"
		modified = "2023-12-05"
		reference = "https://www.barracuda.com/company/legal/esg-vulnerability"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/mal_lnx_barracuda_cve_2023_2868.yar#L2-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "57e9afb2f6928656242b8257cc3b98ae3b03e38c75ad40b544e3fc6afaea794d"
		score = 75
		quality = 85
		tags = "CVE-2023-2868, FILE"
		hash1 = "8849a3273e0362c45b4928375d196714224ec22cb1d2df5d029bf57349860347"

	strings:
		$sc1 = { 00 2D 63 00 2F 62 69 6E 2F 73 68 00 }
		$s1 = "SSLShell"

	condition:
		uint32be( 0 ) == 0x7f454c46 and uint16( 0x10 ) == 0x0002 and filesize < 5MB and all of them
}

rule SIGNATURE_BASE_MAL_ELF_SALTWATER_Jun23_1 : CVE_2023_2868 FILE
{
	meta:
		description = "Detects SALTWATER malware used in Barracuda ESG exploitations (CVE-2023-2868)"
		author = "Florian Roth"
		id = "10a038f6-6096-5d3a-aaf5-db441685102b"
		date = "2023-06-07"
		modified = "2023-12-05"
		reference = "https://www.barracuda.com/company/legal/esg-vulnerability"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/mal_lnx_barracuda_cve_2023_2868.yar#L21-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "cb35898c0ee726170da93b4364920ac065f083f9f02db8eb5d293b1ce127cb78"
		score = 80
		quality = 85
		tags = "CVE-2023-2868, FILE"
		hash1 = "601f44cc102ae5a113c0b5fe5d18350db8a24d780c0ff289880cc45de28e2b80"

	strings:
		$x1 = "libbindshell.so"
		$s1 = "ShellChannel"
		$s2 = "MyWriteAll"
		$s3 = "CheckRemoteIp"
		$s4 = "run_cmd"
		$s5 = "DownloadByProxyChannel"
		$s6 = "[-] error: popen failed"
		$s7 = "/home/product/code/config/ssl_engine_cert.pem"

	condition:
		uint16( 0 ) == 0x457f and filesize < 6000KB and ( ( 1 of ( $x* ) and 2 of them ) or 3 of them ) or all of them
}

