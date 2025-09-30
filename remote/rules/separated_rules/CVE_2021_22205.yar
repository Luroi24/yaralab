rule SIGNATURE_BASE_EXPL_Gitlab_CE_RCE_CVE_2021_22205 : CVE_2021_22205
{
	meta:
		description = "Detects signs of exploitation of GitLab CE CVE-2021-22205"
		author = "Florian Roth (Nextron Systems)"
		id = "21cc6fa7-e50d-5b8e-815d-27315ab5635d"
		date = "2021-10-26"
		modified = "2023-12-05"
		reference = "https://security.humanativaspa.it/gitlab-ce-cve-2021-22205-in-the-wild/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_gitlab_cve_2021_22205.yar#L2-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "54b841716a6bd56706c1c38fcda9a27ffd7feba2660602b191e8e347983e578d"
		score = 70
		quality = 85
		tags = "CVE-2021-22205"

	strings:
		$sa1 = "VXNlci5maW5kX2J5KHVzZXJuYW1l" ascii
		$sa2 = "VzZXIuZmluZF9ieSh1c2VybmFtZ" ascii
		$sa3 = "Vc2VyLmZpbmRfYnkodXNlcm5hbW" ascii
		$sb1 = "dXNlci5hZG1pb" ascii
		$sb2 = "VzZXIuYWRtaW" ascii
		$sb3 = "1c2VyLmFkbWlu" ascii
		$sc1 = "dXNlci5zYXZlI" ascii
		$sc2 = "VzZXIuc2F2ZS" ascii
		$sc3 = "1c2VyLnNhdmUh" ascii

	condition:
		1 of ( $sa* ) and 1 of ( $sb* ) and 1 of ( $sc* )
}

rule SIGNATURE_BASE_EXPL_Gitlab_CE_RCE_Malformed_JPG_CVE_2021_22204 : CVE_2021_22204 CVE_2021_22205 FILE
{
	meta:
		description = "Detects malformed JPG files exploting EXIF vulnerability CVE-2021-22204 and used in the exploitation of GitLab vulnerability CVE-2021-22205"
		author = "Florian Roth (Nextron Systems)"
		id = "3d769340-0306-596d-8783-2b37b93a5673"
		date = "2021-10-26"
		modified = "2023-12-05"
		reference = "https://attackerkb.com/topics/D41jRUXCiJ/cve-2021-22205/rapid7-analysis?referrer=blog"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_gitlab_cve_2021_22205.yar#L29-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "0718ad24337acbb746c6e0d7e0b42d2d034ff583ec6fd12b34fda4737d7e78b0"
		score = 70
		quality = 58
		tags = "CVE-2021-22204, CVE-2021-22205, FILE"

	strings:
		$h1 = { 41 54 26 54 46 4F 52 4D }
		$sr1 = /\(metadata[\s]{0,3}\([A-Za-z]{1,20} "\\/

	condition:
		filesize < 10KB and $h1 and $sr1
}

