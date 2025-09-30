rule SIGNATURE_BASE_Hatman_Compiled_Python : HATMAN
{
	meta:
		description = "Detects Hatman malware"
		author = "DHS/NCCIC/ICS-CERT"
		id = "fd156669-72b4-59a5-8f36-aac21d7b3105"
		date = "2017-12-19"
		modified = "2023-12-05"
		reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hatman.yar#L86-L95"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "a18018e4c6ea5b7ab6e1dbdc050e565f66520676565db6d352f58a786097960f"
		score = 75
		quality = 85
		tags = "HATMAN"

	condition:
		SIGNATURE_BASE_Hatman_Nullsub_PRIVATE and SIGNATURE_BASE_Hatman_Setstatus_PRIVATE and SIGNATURE_BASE_Hatman_Dividers_PRIVATE
}

rule SIGNATURE_BASE_Hatman_Injector : HATMAN
{
	meta:
		description = "Detects Hatman malware"
		author = "DHS/NCCIC/ICS-CERT"
		id = "b939b83d-cc4a-5998-89a7-8abf8d0b8592"
		date = "2017-12-19"
		modified = "2023-01-09"
		reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hatman.yar#L96-L106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "19edf44bec6e1cbccefa145c5ae1bf0820729a80ac3ef1c8e7100b465b487e3c"
		score = 75
		quality = 85
		tags = "HATMAN"

	condition:
		(SIGNATURE_BASE_Hatman_Memcpy_PRIVATE and SIGNATURE_BASE_Hatman_Origaddr_PRIVATE and SIGNATURE_BASE_Hatman_Loadoff_PRIVATE )
}

rule SIGNATURE_BASE_Hatman_Payload : HATMAN
{
	meta:
		description = "Detects Hatman malware"
		author = "DHS/NCCIC/ICS-CERT"
		id = "9ef57fca-a536-5937-8510-b410f735a73e"
		date = "2017-12-19"
		modified = "2023-12-05"
		reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hatman.yar#L107-L116"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "9a6e5d2c2f2be35e6dc8b418e33419977460006923ecd9f029cacf51d8c0477a"
		score = 75
		quality = 85
		tags = "HATMAN"

	condition:
		(SIGNATURE_BASE_Hatman_Memcpy_PRIVATE and SIGNATURE_BASE_Hatman_Origcode_PRIVATE and SIGNATURE_BASE_Hatman_Mftmsr_PRIVATE ) and not ( SIGNATURE_BASE_Hatman_Origaddr_PRIVATE and SIGNATURE_BASE_Hatman_Loadoff_PRIVATE )
}

