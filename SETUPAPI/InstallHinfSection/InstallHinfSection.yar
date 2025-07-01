rule Suspicious_INF_RunCommands
{
    meta:
        author = "Dana Behling"
        description = "Detects suspicious INF files that abuse InstallHinfSectionW for command execution"
        reference = "Windows API Abuse Atlas – InstallHinfSectionW"
        date = "2025-07-01"
        threat_level = 3

    strings:
        $run_pre = "RunPreSetupCommands"
        $run_post = "RunPostSetupCommands"
        $calc = "cmd.exe /c calc.exe" nocase
        $powershell = "powershell.exe" nocase
        $default = "[DefaultInstall]"

    condition:
        $default and any of ($run_pre, $run_post) and any of ($calc, $powershell)
}
