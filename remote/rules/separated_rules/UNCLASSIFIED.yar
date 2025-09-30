rule SIGNATURE_BASE_WEBSHELL_ASPX_Simpleseesharp : WEBSHELL UNCLASSIFIED FILE
{
	meta:
		description = "A simple ASPX Webshell that allows an attacker to write further files to disk."
		author = "threatintel@volexity.com"
		id = "469fdf5c-e09e-5d44-a2e6-0864dcd0e18a"
		date = "2021-03-01"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hafnium.yar#L121-L136"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
		logic_hash = "6f62249a68bae94e5cbdb4319ea5cde9dc071ec7a4760df3aafe78bc1e072c30"
		score = 75
		quality = 85
		tags = "WEBSHELL, UNCLASSIFIED, FILE"

	strings:
		$header = "<%@ Page Language=\"C#\" %>"
		$body = "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"

	condition:
		$header at 0 and $body and filesize < 1KB
}

