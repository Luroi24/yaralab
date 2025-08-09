rule SIGNATURE_BASE_EXPL_Citrix_Netscaler_ADC_Forensicartifacts_CVE_2023_3519_Jul23_2 : CVE_2023_3519 FILE
{
	meta:
		description = "Detects forensic artifacts found after an exploitation of Citrix NetScaler ADC CVE-2023-3519"
		author = "Florian Roth"
		id = "471ce547-0133-5836-b9d1-02c932ecfd1e"
		date = "2023-07-21"
		modified = "2023-12-05"
		reference = "https://www.cisa.gov/sites/default/files/2023-07/aa23-201a_csa_threat_actors_exploiting_citrix-cve-2023-3519_to_implant_webshells.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar#L27-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "48d4225d0935084003f7a98c554d7c4722a91290dfe190001da52bce332b3f7d"
		score = 70
		quality = 85
		tags = "CVE-2023-3519, FILE"

	strings:
		$s1 = "tar -czvf - /var/tmp/all.txt" ascii fullword
		$s2 = "-out /var/tmp/test.tar.gz" ascii
		$s3 = "/test.tar.gz /netscaler/"

	condition:
		filesize < 10MB and 1 of them
}

rule SIGNATURE_BASE_EXPL_Citrix_Netscaler_ADC_Forensicartifacts_CVE_2023_3519_Jul23_3 : CVE_2023_3519 FILE
{
	meta:
		description = "Detects forensic artifacts found after an exploitation of Citrix NetScaler ADC CVE-2023-3519"
		author = "Florian Roth"
		id = "2f40b423-f1da-5711-ac4f-18de77cd52d0"
		date = "2023-07-24"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/citrix-zero-day-espionage"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar#L43-L61"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "e78e1a788503b841ed0f4e5cd415eb35d8911092778120d7fd061ed20820da37"
		score = 70
		quality = 85
		tags = "CVE-2023-3519, FILE"

	strings:
		$x1 = "cat /flash/nsconfig/ns.conf >>" ascii
		$x2 = "cat /nsconfig/.F1.key >>" ascii
		$x3 = "openssl base64 -d < /tmp/" ascii
		$x4 = "cp /usr/bin/bash /var/tmp/bash" ascii
		$x5 = "chmod 4775 /var/tmp/bash"
		$x6 = "pwd;pwd;pwd;pwd;pwd;"
		$x7 = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"

	condition:
		filesize < 10MB and 1 of them
}

rule SIGNATURE_BASE_LOG_EXPL_Citrix_Netscaler_ADC_Exploitation_Attempt_CVE_2023_3519_Jul23_1 : CVE_2023_3519
{
	meta:
		description = "This YARA rule detects forensic artifacts that appear following an attempted exploitation of Citrix NetScaler ADC CVE-2023-3519. The rule identifies an attempt to access the vulnerable function using an overly long URL, a potential sign of attempted exploitation. However, it does not confirm whether such an attempt was successful."
		author = "Florian Roth"
		id = "7dfe4130-d976-5d6d-a05d-ccadefe45406"
		date = "2023-07-27"
		modified = "2023-12-05"
		reference = "https://blog.assetnote.io/2023/07/24/citrix-rce-part-2-cve-2023-3519/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar#L63-L77"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "7ad3164c5b2616b12a513a2bb3736d530769e75fca03346a72351a27b8343b2a"
		score = 65
		quality = 60
		tags = "CVE-2023-3519"

	strings:
		$sr1 = /GWTEST FORMS SSO: Parse=0; URLLEN=([2-9][0-9]{2}|[0-9]{4,20}); Event: start=0x/
		$s1 = ", type=1; Target: start=0x"

	condition:
		all of them
}

