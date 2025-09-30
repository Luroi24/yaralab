rule SIGNATURE_BASE_LOG_SUSP_EXPL_POC_Vmware_Workspace_ONE_CVE_2022_22954_Apr22_ : CVE_2022_22954
{
	meta:
		description = "Detects payload as seen in PoC code to exploit Workspace ONE Access freemarker server-side template injection CVE-2022-22954"
		author = "Florian Roth"
		id = "c54a3a7a-aafc-52d4-863c-ed254b0da527"
		date = "2022-04-08"
		modified = "2025-03-29"
		old_rule_name = "EXPL_POC_VMWare_Workspace_ONE_CVE_2022_22954_Apr22"
		reference = "https://twitter.com/rwincey/status/1512241638994853891/photo/1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2022_22954_vmware_workspace_one.yar#L36-L54"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "3c383f197da1e043e632c4d4de03fa7ff42e3fb6fa7824f326874446bcd13588"
		score = 60
		quality = 85
		tags = "CVE-2022-22954"

	strings:
		$x1 = "66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28" ascii
		$fp2 = "ModSecurity"
		$fp3 = " 302 -"

	condition:
		1 of ( $x* ) and not 1 of ( $fp* )
}

