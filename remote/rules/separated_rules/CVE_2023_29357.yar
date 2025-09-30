rule SIGNATURE_BASE_LOG_EXPL_Sharepoint_CVE_2023_29357_Sep23_1 : CVE_2023_29357
{
	meta:
		description = "Detects log entries that could indicate a successful exploitation of CVE-2023-29357 on Microsoft SharePoint servers with the published Python POC"
		author = "Florian Roth (with help from @LuemmelSec)"
		id = "9fa77216-c0d6-55e5-bbcc-adb9438ca456"
		date = "2023-09-28"
		modified = "2023-10-01"
		reference = "https://twitter.com/Gi7w0rm/status/1706764212704591953?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_sharepoint_cve_2023_29357.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "03e3a4715c8683dc8d03ad6720c1c9b40482bd0bfa3020aa1152565ec9ec929f"
		score = 70
		quality = 60
		tags = "CVE-2023-29357"

	strings:
		$xr1 = /GET [a-z\.\/_]{0,40}\/web\/(siteusers|currentuser) - (80|443) .{10,200} (python-requests\/[0-9\.]{3,8}|-) [^ ]{1,160} [^4]0[0-9] /

	condition:
		$xr1
}

rule SIGNATURE_BASE_HKTL_EXPL_POC_PY_Sharepoint_CVE_2023_29357_Sep23_1 : CVE_2023_29357 FILE
{
	meta:
		description = "Detects a Python POC to exploit CVE-2023-29357 on Microsoft SharePoint servers"
		author = "Florian Roth"
		id = "2be524ab-f360-56b8-9ce3-e15036855c67"
		date = "2023-10-01"
		modified = "2023-10-01"
		reference = "https://github.com/Chocapikk/CVE-2023-29357"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_sharepoint_cve_2023_29357.yar#L22-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "fec7762ab23ba5ee9e793000d080b1d64b93157c6ead9e6939ccfb3c168dd360"
		score = 80
		quality = 85
		tags = "CVE-2023-29357, FILE"

	strings:
		$x1 = "encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')"

	condition:
		filesize < 30KB and $x1
}

rule SIGNATURE_BASE_HKTL_EXPL_POC_NET_Sharepoint_CVE_2023_29357_Sep23_1 : CVE_2023_29357 FILE
{
	meta:
		description = "Detects a C# POC to exploit CVE-2023-29357 on Microsoft SharePoint servers"
		author = "Florian Roth"
		id = "aa6aeb00-b162-538c-a670-cbff525dd8f1"
		date = "2023-10-01"
		modified = "2023-12-05"
		reference = "https://github.com/LuemmelSec/CVE-2023-29357"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_sharepoint_cve_2023_29357.yar#L37-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "cf621cc9c5074f531df61623b09db68478e94ae6a9a7acc26aa8d9dde79bd30c"
		score = 80
		quality = 85
		tags = "CVE-2023-29357, FILE"

	strings:
		$x1 = "{f22d2de0-606b-4d16-98d5-421f3f1ba8bc}" ascii wide
		$x2 = "{F22D2DE0-606B-4D16-98D5-421F3F1BA8BC}" ascii wide
		$s1 = "Bearer"
		$s2 = "hashedprooftoken"
		$s3 = "/_api/web/"
		$s4 = "X-PROOF_TOKEN"
		$s5 = "00000003-0000-0ff1-ce00-000000000000"
		$s6 = "IsSiteAdmin"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and ( 1 of ( $x* ) or all of ( $s* ) )
}

