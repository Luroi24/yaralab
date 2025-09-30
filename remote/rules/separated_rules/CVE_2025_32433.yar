rule SIGNATURE_BASE_VULN_Erlang_OTP_SSH_CVE_2025_32433_Apr25 : CVE_2025_32433 FILE
{
	meta:
		description = "Detects binaries vulnerable to CVE-2025-32433 in Erlang/OTP SSH"
		author = "Pierre-Henri Pezier, Florian Roth"
		id = "2a149d28-9dba-546d-abfe-79c0ced34b12"
		date = "2025-04-18"
		modified = "2025-04-28"
		reference = "https://www.upwind.io/feed/cve-2025-32433-critical-erlang-otp-ssh-vulnerability-cvss-10"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/vuln_erlang_otp_ssh_cve_2025_32433.yar#L1-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "77d23956bd467a6eb56a91fa7a4bd939873363cd101a9d21b5b298c7b2e6c1ec"
		score = 60
		quality = 85
		tags = "CVE-2025-32433, FILE"

	strings:
		$a1 = { 46 4F 52 31 ?? ?? ?? ?? 42 45 41 4D }
		$s1 = "ssh_connection.erl"
		$fix1 = "chars_limit"
		$fix2 = "allow    macro_log"
		$fix3 = "logger"
		$fix4 = "max_log_item_len"

	condition:
		filesize < 1MB and $a1 at 0 and $s1 and not 1 of ( $fix* )
}

