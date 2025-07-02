rule Suspicious_INF_RunCommands
{
    meta:
        description = "Detects suspicious INF files that abuse InstallHinfSectionW for command execution"
        reference = "Windows API Abuse Atlas – InstallHinfSectionW"

    strings:
        $run_pre = "RunPreSetupCommands"
        $run_post = "RunPostSetupCommands"
        $calc = "cmd.exe /c calc.exe" nocase
        $powershell = "powershell.exe" nocase
        $default = "[DefaultInstall]"

    condition:
        $default and any of ($run_pre, $run_post) and any of ($calc, $powershell)
}
