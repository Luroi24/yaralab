rule SECUINFRA_DROPPER_Unknown_1 : DROPPER HTA FILE
{
	meta:
		description = "Detects unknown HTA Dropper"
		author = "SECUINFRA Falcon Team"
		id = "70c06b9d-8474-5b6e-bd9c-d45a25585ee9"
		date = "2022-10-02"
		modified = "2022-02-19"
		reference = "https://bazaar.abuse.ch/sample/c2bf8931028e0a18eeb8f1a958ade0ab9d64a00c16f72c1a3459f160f0761348/"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Dropper/unknown.yar#L1-L21"
		license_url = "N/A"
		hash = "1749f4127bba3f7204710286b1252e14"
		logic_hash = "d02874514bcb6c3603d1bfee702ec9e18c15153bc14a55ca8d637308c3f35a75"
		score = 75
		quality = 43
		tags = "DROPPER, HTA, FILE"

	strings:
		$a1 = "<script type=\"text/vbscript\" LANGUAGE=\"VBScript\" >"
		$a2 = "Function XmlTime(t)"
		$a3 = "C:\\ProgramData\\"
		$a4 = "wscript.exe"
		$a5 = "Array" nocase
		$b = "chr" nocase

	condition:
		filesize < 70KB and all of ( $a* ) and #b > 7
}

