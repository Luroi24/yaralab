rule SIGNATURE_BASE_SUSP_ZIP_Ntdsdit : T1003_003 FILE
{
	meta:
		description = "Detects ntds.dit files in ZIP archives that could be a left over of administrative activity or traces of data exfiltration"
		author = "Florian Roth (Nextron Systems)"
		id = "131ed73d-bb34-5ff6-b145-f95e4469d7f9"
		date = "2020-08-10"
		modified = "2023-12-05"
		reference = "https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/generic_dumps.yar#L47-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "371e30f50d96c884bd55ffc10d049d0ada881304746564a99dec0e8efad87602"
		score = 50
		quality = 85
		tags = "T1003_003, FILE"

	strings:
		$s1 = "ntds.dit" ascii

	condition:
		uint16( 0 ) == 0x4b50 and $s1 in ( 0 .. 256 )
}

