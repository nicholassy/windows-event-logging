<# 
Filtered Event Report (Windows 11) -> PDF
- Handles each EventID individually to output only important fields (switch per EventID).
- Groups events by your clauses (a, b, c, d, e, f, g).
- Excludes system-generated events (SYSTEM/LOCAL SERVICE/NETWORK SERVICE + computer accounts like DESKTOP$).
- Outputs a PDF report using Microsoft Edge headless print (no extra modules needed).

USAGE:
  .\FilteredEventsToPdf.ps1
  .\FilteredEventsToPdf.ps1 -DaysBack 72 -OutPdf "C:\Reports\event_report.pdf" -IncludeMessage

NOTES:
- Clause f (SECRET file access) requires Object Access auditing + SACLs on target files/folders.
- Run PowerShell as Administrator to read Security log reliably.
#>

[CmdletBinding()]
param(
    [int]$DaysBack = 90,
    [string]$OutPdf = "$env:USERPROFILE\Desktop\WindowsLog_Report.pdf",
    [switch]$IncludeMessage
)

$ErrorActionPreference = "Stop"

$StartTime = (Get-Date).AddDays(-$DaysBack)

# -----------------------------
# Clause mapping (grouping)
# -----------------------------
$ClauseMap = [ordered]@{
    "a) Privileged/power user accounts & access rights" = @(
        4720,4722,4723,4724,4725,4726,4738,4740,4767,
        4728,4729,4732,4733,4756,4757,
        4717,4718,
        4672
    )
    "b) Security configuration changes (auth/encryption/logging/audit)" = @(
        4719,4715,4902,4904,4905,4906,4912,
        4768,4769,4771,4776,
        4886,4887,4890,5058
    )
    "c) Services or scheduled jobs created/changed" = @(
        4697,7045,7036,7040,
        4698,4699,4700,4701,4702
    )
    "d) Software/patch install, uninstall, modification" = @(
        1033,1034,11707,11724,
        19,20,21,
        6416,6419,6420,
        7045
    )
    "e) Logs modified/cleared/tampering indicators" = @(
        1102,1100,104,4715,4719
    )
    "f) SECRET file access/modify/delete (Object Access + SACLs required)" = @(
        4656,4663,4658,4660,4670
    )
    "g) Failed logon / lockout" = @(
        4625,4740,4771,4776
    )
}

# -----------------------------
# Which logs + event IDs to scan (based on earlier list + your additions)
# -----------------------------
$SecurityEventIds = @(
    4624,4625,4634,4648,
    4672,4673,4674,
    4696,4697,4698,4699,4700,4701,4702,
    4715,4717,4718,4719,
    4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,4738,
    4740,4756,4757,4767,
    4768,4769,4771,4776,
    4886,4887,4890,4902,4904,4905,4906,4912,
    5058,
    4656,4663,4658,4660,4670,
    1100,1102
) | Sort-Object -Unique

$ApplicationEventIds = @(11707,11724,1033,1034) | Sort-Object -Unique

$SystemEventIds = @(
    104,7036,7040,7045,
    19,20,21,
    6416,6419,6420
) | Sort-Object -Unique

$LogsToQuery = @(
    @{ LogName="Security";     Ids=$SecurityEventIds }
    @{ LogName="Application";  Ids=$ApplicationEventIds }
    @{ LogName="System";       Ids=$SystemEventIds }
    # Optional - only if you want update operational channel too:
    @{ LogName="Microsoft-Windows-WindowsUpdateClient/Operational"; Ids=@(19,20,21) }
)

# -----------------------------
# System-generated offender filtering
# -----------------------------
$SystemAccounts = @(
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "ANONYMOUS LOGON",
    "NT AUTHORITY\SYSTEM"
)

function Resolve-SidToName {
    param([string]$Sid)
    if (-not $Sid) { return $null }
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        return $sidObj.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        return $Sid
    }
}

function Get-EventDataMap {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)
    $xml = [xml]$Event.ToXml()

    $map = @{}
    if ($xml.Event.EventData -and $xml.Event.EventData.Data) {
        foreach ($d in $xml.Event.EventData.Data) {
            $name = [string]$d.Name
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                $map[$name] = [string]$d.'#text'
            }
        }
    }

    if ($xml.Event.UserData) {
        foreach ($node in $xml.Event.UserData.ChildNodes) {
            foreach ($child in $node.ChildNodes) {
                if ($child.Name -and $child.InnerText) {
                    $map["UserData:$($child.Name)"] = $child.InnerText
                }
            }
        }
    }

    return $map
}

function Get-OffenderFromEvent {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    function Clean($s) {
        if (-not $s) { return $null }
        $t = ($s.ToString()).Trim()
        if ($t -eq "" -or $t -eq "-" -or $t -eq "N/A") { return $null }
        return $t
    }

    # 1) Use EventRecord.UserId (SID) when available (often for System/Application)
    try {
        if ($Event.UserId) {
            $name = Clean (Resolve-SidToName -Sid $Event.UserId.Value)
            if ($name) { return $name }
        }
    } catch {}

    # 2) Use XML EventData fields
    try {
        $d = Get-EventDataMap -Event $Event

        $subUser = Clean $d["SubjectUserName"]
        $subDom  = Clean $d["SubjectDomainName"]
        $tgtUser = Clean $d["TargetUserName"]
        $tgtDom  = Clean $d["TargetDomainName"]
        $acct    = Clean $d["AccountName"]

        $candidates = @()

        if ($subDom -and $subUser) { $candidates += "$subDom\$subUser" }
        if ($subUser) { $candidates += $subUser }

        if ($tgtDom -and $tgtUser) { $candidates += "$tgtDom\$tgtUser" }
        if ($tgtUser) { $candidates += $tgtUser }

        if ($acct) { $candidates += $acct }

        # SID fields in EventData
        foreach ($sidKey in @("SubjectUserSid","TargetUserSid","AccountSid")) {
            if ($d.ContainsKey($sidKey) -and (Clean $d[$sidKey])) {
                $translated = Clean (Resolve-SidToName -Sid $d[$sidKey])
                if ($translated) { $candidates += $translated }
            }
        }

        foreach ($c in $candidates) {
            $cc = Clean $c
            if ($cc) { return $cc }
        }
    } catch {}

    # 3) Fallback: parse from message (best-effort)
    try {
        $msg = $Event.Message
        if ($msg) {
            $acct = $null; $dom = $null
            if ($msg -match '(?m)^\s*Account Name:\s*(.+?)\s*$') { $acct = Clean $Matches[1] }
            if ($msg -match '(?m)^\s*Account Domain:\s*(.+?)\s*$') { $dom  = Clean $Matches[1] }
            if ($dom -and $acct -and $acct -ne "-") { return "$dom\$acct" }
            if ($acct -and $acct -ne "-") { return $acct }
        }
    } catch {}

    return $null
}

function Get-ClauseForEventId {
    param([int]$EventId)
    foreach ($k in $ClauseMap.Keys) {
        if ($ClauseMap[$k] -contains $EventId) { return $k }
    }
    return "Unmapped"
}

function New-FilteredEventObject {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    $id   = [int]$Event.Id
    $log  = [string]$Event.LogName
    $time = [datetime]$Event.TimeCreated
    $comp = [string]$Event.MachineName
    $prov = [string]$Event.ProviderName

    $d = Get-EventDataMap -Event $Event

    function Pick([string[]]$keys) {
        foreach ($k in $keys) {
            if ($d.ContainsKey($k) -and -not [string]::IsNullOrWhiteSpace($d[$k])) { return $d[$k] }
        }
        return $null
    }

    $offender = Get-OffenderFromEvent -Event $Event

    # Exclude system-generated events:
    # - well-known system/service accounts
    # - computer accounts ending with $
    if ($offender) {
        if ($SystemAccounts -contains $offender.ToUpper()) { return $null }
        if ($offender -match '\$$') { return $null } # treat machine accounts as "system-generated"
    } else {
        # If no offender can be determined, treat as system-generated and skip
        return $null
    }

    $base = [ordered]@{
        Clause      = Get-ClauseForEventId -EventId $id
        TimeCreated = $time
        LogName     = $log
        Provider    = $prov
        EventID     = $id
        Offender    = $offender
        Description = $null
        Details     = $null
    }

    # --- Per-EventID handling (keep it "like your script") ---
    switch ($id) {

        4624 {
            $logonType = Pick @("LogonType")
            $ip   = Pick @("IpAddress","WorkstationName")
            $tgt  = ("{0}\{1}" -f (Pick @("TargetDomainName","TargetUserDomain")), (Pick @("TargetUserName","TargetUser"))).Trim("\")
            $base.Description = "Successful logon (Type $logonType) for $tgt from $ip"
            $base.Details = "Target=$tgt; LogonType=$logonType; IP/WS=$ip; Process=$(Pick @("ProcessName")); AuthPkg=$(Pick @("AuthenticationPackageName"))"
        }

        4625 {
            $tgt  = ("{0}\{1}" -f (Pick @("TargetDomainName","TargetUserDomain")), (Pick @("TargetUserName","TargetUser"))).Trim("\")
            $logonType = Pick @("LogonType")
            $ip   = Pick @("IpAddress","WorkstationName")
            $base.Description = "Failed logon (Type $logonType) for $tgt from $ip"
            $base.Details = "Target=$tgt; LogonType=$logonType; IP/WS=$ip; Status=$(Pick @("Status")); SubStatus=$(Pick @("SubStatus")); Reason=$(Pick @("FailureReason")); Process=$(Pick @("ProcessName"))"
        }

        4634 {
            $tgt  = ("{0}\{1}" -f (Pick @("TargetDomainName","TargetUserDomain")), (Pick @("TargetUserName","TargetUser"))).Trim("\")
            $logonType = Pick @("LogonType")
            $base.Description = "Logoff for $tgt (Type $logonType)"
            $base.Details = "Target=$tgt; LogonType=$logonType"
        }

        4648 {
            $actor  = ("{0}\{1}" -f (Pick @("SubjectDomainName")), (Pick @("SubjectUserName"))).Trim("\")
            $target = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $server = Pick @("TargetServerName")
            $base.Description = "Explicit credentials used by $actor to access $server as $target"
            $base.Details = "Actor=$actor; Target=$target; Server=$server; Process=$(Pick @("ProcessName")); IP=$(Pick @("IpAddress"))"
        }

        4768 {
            $tgt  = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $ip   = Pick @("IpAddress")
            $svc  = Pick @("ServiceName")
            $base.Description = "Kerberos TGT requested for $tgt"
            $base.Details = "Target=$tgt; Service=$svc; IP=$ip; TicketOptions=$(Pick @("TicketOptions")); Status=$(Pick @("Status"))"
        }

        4769 {
            $tgt  = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $svc  = Pick @("ServiceName")
            $ip   = Pick @("IpAddress")
            $base.Description = "Kerberos service ticket requested by $tgt for $svc"
            $base.Details = "Target=$tgt; Service=$svc; IP=$ip; TicketEncryptionType=$(Pick @("TicketEncryptionType")); Status=$(Pick @("Status"))"
        }

        4771 {
            $tgt = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $ip  = Pick @("IpAddress")
            $base.Description = "Kerberos pre-auth failed for $tgt"
            $base.Details = "Target=$tgt; IP=$ip; FailureCode=$(Pick @("FailureCode")); PreAuthType=$(Pick @("PreAuthType"))"
        }

        4776 {
            $tgt = ("{0}\{1}" -f (Pick @("TargetDomainName","Workstation")), (Pick @("TargetUserName"))).Trim("\")
            $ws  = Pick @("Workstation")
            $base.Description = "NTLM authentication attempt for $tgt"
            $base.Details = "Target=$tgt; Workstation=$ws; Status=$(Pick @("Status"))"
        }

        # --- Privilege use / privileged logon ---
        4672 {
            $who   = ("{0}\{1}" -f (Pick @("SubjectDomainName")), (Pick @("SubjectUserName"))).Trim("\")
            $privs = Pick @("PrivilegeList")
            $base.Description = "Special privileges assigned to $who"
            $base.Details = "User=$who; Privileges=$privs"
        }

        4673 {
            $who = ("{0}\{1}" -f (Pick @("SubjectDomainName")), (Pick @("SubjectUserName"))).Trim("\")
            $svc = Pick @("Service")
            $proc = Pick @("ProcessName")
            $priv = Pick @("PrivilegeList")
            $base.Description = "Privileged service called by $who"
            $base.Details = "User=$who; Service=$svc; Process=$proc; Privileges=$priv"
        }

        4674 {
            $who = ("{0}\{1}" -f (Pick @("SubjectDomainName")), (Pick @("SubjectUserName"))).Trim("\")
            $objType = Pick @("ObjectType")
            $objName = Pick @("ObjectName")
            $priv = Pick @("PrivilegeList")
            $proc = Pick @("ProcessName")
            $base.Description = "Sensitive privilege used by $who"
            $base.Details = "User=$who; ObjectType=$objType; ObjectName=$objName; Process=$proc; Privileges=$priv"
        }

        4696 {
            $who = ("{0}\{1}" -f (Pick @("SubjectDomainName")), (Pick @("SubjectUserName"))).Trim("\")
            $target = Pick @("TargetUserName","TargetUser")
            $base.Description = "Primary token assigned (possible elevation)"
            $base.Details = "Actor=$who; Target=$target"
        }

        # --- Services & scheduled tasks ---
        4697 {
            $svcName  = Pick @("ServiceName")
            $svcFile  = Pick @("ServiceFileName")
            $startType = Pick @("StartType")
            $runAs    = Pick @("AccountName")
            $base.Description = "Service installed: $svcName"
            $base.Details = "Service=$svcName; File=$svcFile; StartType=$startType; RunAs=$runAs"
        }

        4698 {
            $task = Pick @("TaskName")
            $base.Description = "Scheduled task created: $task"
            $base.Details = "TaskName=$task; TaskContent=$(Pick @("TaskContent"))"
        }

        4699 {
            $task = Pick @("TaskName")
            $base.Description = "Scheduled task deleted: $task"
            $base.Details = "TaskName=$task"
        }

        4700 {
            $task = Pick @("TaskName")
            $base.Description = "Scheduled task enabled: $task"
            $base.Details = "TaskName=$task"
        }

        4701 {
            $task = Pick @("TaskName")
            $base.Description = "Scheduled task disabled: $task"
            $base.Details = "TaskName=$task"
        }

        4702 {
            $task = Pick @("TaskName")
            $base.Description = "Scheduled task updated: $task"
            $base.Details = "TaskName=$task; TaskContent=$(Pick @("TaskContent"))"
        }

        # --- Security policy / audit changes ---
        4715 {
            $who = ("{0}\{1}" -f (Pick @("SubjectDomainName")), (Pick @("SubjectUserName"))).Trim("\")
            $base.Description = "Audit policy changed (4715)"
            $base.Details = "Actor=$who; CategoryId=$(Pick @("CategoryId")); SubcategoryGuid=$(Pick @("SubcategoryGuid")); Changes=$(Pick @("Changes","AuditPolicyChanges"))"
        }

        4717 {
            $target = ("{0}\{1}" -f (Pick @("AccountDomain","TargetDomainName","TargetUserDomain")), (Pick @("AccountName","TargetUserName"))).Trim("\")
            $rights = Pick @("GrantedAccess","Accesses","PrivilegeList")
            $base.Description = "System security access granted to $target"
            $base.Details = "Target=$target; GrantedAccess/Rights=$rights"
        }

        4718 {
            $target = ("{0}\{1}" -f (Pick @("AccountDomain","TargetDomainName","TargetUserDomain")), (Pick @("AccountName","TargetUserName"))).Trim("\")
            $rights = Pick @("RemovedAccess","Accesses","PrivilegeList")
            $base.Description = "System security access removed from $target"
            $base.Details = "Target=$target; RemovedAccess/Rights=$rights"
        }

        4719 {
            $cat = Pick @("CategoryId","SubcategoryGuid","SubcategoryId")
            $chg = Pick @("AuditPolicyChanges","Changes","NewValue","OldValue")
            $base.Description = "Audit policy changed"
            $base.Details = "Category/Subcategory=$cat; Changes=$chg"
        }

        4902 {
            $base.Description = "Per-user audit policy table created"
            $base.Details = "UserSid=$(Pick @("TargetUserSid","UserSid")); CategoryId=$(Pick @("CategoryId")); SubcategoryGuid=$(Pick @("SubcategoryGuid"))"
        }

        4904 {
            $base.Description = "Audit policy settings changed"
            $base.Details = "CategoryId=$(Pick @("CategoryId")); SubcategoryGuid=$(Pick @("SubcategoryGuid")); Changes=$(Pick @("Changes","AuditPolicyChanges"))"
        }

        4905 {
            $base.Description = "Audit policy settings changed (4905)"
            $base.Details = "CategoryId=$(Pick @("CategoryId")); SubcategoryGuid=$(Pick @("SubcategoryGuid")); Changes=$(Pick @("Changes","AuditPolicyChanges"))"
        }

        4906 {
            $base.Description = "CrashOnAuditFail changed (audit failure behavior)"
            $base.Details = "OldValue=$(Pick @("OldValue")); NewValue=$(Pick @("NewValue"))"
        }

        4912 {
            $base.Description = "Per-user audit policy changed"
            $base.Details = "TargetUserSid=$(Pick @("TargetUserSid")); CategoryId=$(Pick @("CategoryId")); SubcategoryGuid=$(Pick @("SubcategoryGuid")); Changes=$(Pick @("Changes","AuditPolicyChanges"))"
        }

        # --- Account management ---
        4720 {
            $target = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $sid    = Pick @("TargetSid")
            $base.Description = "User created: $target"
            $base.Details = "Target=$target; SID=$sid; DisplayName=$(Pick @("DisplayName")); UAC=$(Pick @("UserAccountControl"))"
        }

        4722 {
            $target = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $base.Description = "User enabled: $target"
            $base.Details = "Target=$target; SID=$(Pick @("TargetSid"))"
        }

        4723 {
            $target = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $base.Description = "Password change attempt for $target"
            $base.Details = "Target=$target"
        }

        4724 {
            $target = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $base.Description = "Password reset attempt for $target"
            $base.Details = "Target=$target"
        }

        4725 {
            $target = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $base.Description = "User disabled: $target"
            $base.Details = "Target=$target; SID=$(Pick @("TargetSid"))"
        }

        4726 {
            $target = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $sid    = Pick @("TargetSid")
            $base.Description = "User deleted: $target"
            $base.Details = "Target=$target; SID=$sid"
        }

        4728 {
            $member = Pick @("MemberName")
            $grp = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName","GroupName"))).Trim("\")
            $base.Description = "Member added to global group: $grp"
            $base.Details = "Group=$grp; Member=$member; MemberSid=$(Pick @("MemberSid"))"
        }

        4729 {
            $member = Pick @("MemberName")
            $grp = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName","GroupName"))).Trim("\")
            $base.Description = "Member removed from global group: $grp"
            $base.Details = "Group=$grp; Member=$member; MemberSid=$(Pick @("MemberSid"))"
        }

        4732 {
            $member = Pick @("MemberName")
            $grp = Pick @("GroupName")
            $base.Description = "Member added to local group: $grp"
            $base.Details = "Group=$grp; Member=$member; MemberSid=$(Pick @("MemberSid"))"
        }

        4733 {
            $member = Pick @("MemberName")
            $grp = Pick @("GroupName")
            $base.Description = "Member removed from local group: $grp"
            $base.Details = "Group=$grp; Member=$member; MemberSid=$(Pick @("MemberSid"))"
        }

        4738 {
            $target = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $base.Description = "User account changed: $target"
            $base.Details = "Target=$target; SID=$(Pick @("TargetSid")); ChangedAttributes=$(Pick @("ChangedAttributes","UserAccountControl"))"
        }

        4756 {
            $member = Pick @("MemberName")
            $grp = Pick @("GroupName")
            $base.Description = "Member added to universal group: $grp"
            $base.Details = "Group=$grp; Member=$member; MemberSid=$(Pick @("MemberSid"))"
        }

        4757 {
            $member = Pick @("MemberName")
            $grp = Pick @("GroupName")
            $base.Description = "Member removed from universal group: $grp"
            $base.Details = "Group=$grp; Member=$member; MemberSid=$(Pick @("MemberSid"))"
        }

        4740 {
            $target = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $caller = Pick @("CallerComputerName")
            $base.Description = "Account locked out: $target"
            $base.Details = "Target=$target; CallerComputer=$caller"
        }

        4767 {
            $target = ("{0}\{1}" -f (Pick @("TargetDomainName")), (Pick @("TargetUserName"))).Trim("\")
            $base.Description = "Account unlocked: $target"
            $base.Details = "Target=$target"
        }

        # --- Cert / crypto-ish (best-effort fields; may vary by setup) ---
        4886 {
            $req = Pick @("RequestID","RequestId")
            $tmpl = Pick @("CertificateTemplate")
            $base.Description = "Certificate request received"
            $base.Details = "RequestID=$req; Template=$tmpl; Requester=$(Pick @("RequesterName","AccountName"))"
        }

        4887 {
            $req = Pick @("RequestID","RequestId")
            $tmpl = Pick @("CertificateTemplate")
            $base.Description = "Certificate issued"
            $base.Details = "RequestID=$req; Template=$tmpl; Requester=$(Pick @("RequesterName","AccountName"))"
        }

        4890 {
            $serial = Pick @("SerialNumber")
            $base.Description = "Certificate revoked"
            $base.Details = "SerialNumber=$serial; Reason=$(Pick @("RevocationReason"))"
        }

        5058 {
            $op = Pick @("Operation")
            $key = Pick @("KeyName","KeyFilePath")
            $base.Description = "Key file operation"
            $base.Details = "Operation=$op; Key=$key; Process=$(Pick @("ProcessName"))"
        }

        # --- Object access / SECRET files (requires audit + SACLs) ---
        4656 {
            $obj = Pick @("ObjectName")
            $type = Pick @("ObjectType")
            $acc = Pick @("AccessMask","AccessList","Accesses")
            $base.Description = "Handle requested to object: $obj"
            $base.Details = "ObjectType=$type; ObjectName=$obj; Access=$acc; Process=$(Pick @("ProcessName"))"
        }

        4663 {
            $obj = Pick @("ObjectName")
            $type = Pick @("ObjectType")
            $acc = Pick @("AccessMask","AccessList","Accesses")
            $base.Description = "Object access attempt: $obj"
            $base.Details = "ObjectType=$type; ObjectName=$obj; Access=$acc; Process=$(Pick @("ProcessName"))"
        }

        4658 {
            $obj = Pick @("ObjectName")
            $base.Description = "Handle closed for object: $obj"
            $base.Details = "ObjectName=$obj; Process=$(Pick @("ProcessName"))"
        }

        4660 {
            $obj = Pick @("ObjectName")
            $base.Description = "Object deleted: $obj"
            $base.Details = "ObjectName=$obj; Process=$(Pick @("ProcessName"))"
        }

        4670 {
            $obj = Pick @("ObjectName")
            $base.Description = "Permissions changed on object: $obj"
            $base.Details = "ObjectName=$obj; ObjectType=$(Pick @("ObjectType")); OldSD=$(Pick @("OldSd")); NewSD=$(Pick @("NewSd"))"
        }

        # --- Log tampering indicators ---
        1100 {
            $base.Description = "Event logging service shut down"
            $base.Details = "Log tampering / service disruption indicator"
        }

        1102 {
            $base.Description = "Security audit log was cleared"
            $base.Details = "High priority: log tampering indicator"
        }

        # --- SYSTEM log IDs (service changes / updates / device installs) ---
        104 {
            $base.Description = "Event log was cleared (System)"
            $base.Details = "Log tampering indicator"
        }

        7036 {
            $svc = Pick @("param1","ServiceName")
            $state = Pick @("param2")
            $base.Description = "Service state changed: $svc -> $state"
            $base.Details = "Service=$svc; State=$state"
        }

        7040 {
            $svc = Pick @("param1","ServiceName")
            $stype = Pick @("param2")
            $base.Description = "Service start type changed: $svc"
            $base.Details = "Service=$svc; NewStartType=$stype"
        }

        7045 {
            $svc = Pick @("ServiceName","param1")
            $img = Pick @("ImagePath","param2")
            $base.Description = "New service installed: $svc"
            $base.Details = "Service=$svc; ImagePath=$img"
        }

        19 {
            $kb = Pick @("UpdateTitle","Title")
            $base.Description = "Windows Update installed"
            $base.Details = "Title=$kb; ClientId=$(Pick @("ClientId")); ResultCode=$(Pick @("ResultCode"))"
        }

        20 {
            $kb = Pick @("UpdateTitle","Title")
            $base.Description = "Windows Update failed"
            $base.Details = "Title=$kb; ErrorCode=$(Pick @("ErrorCode")); ResultCode=$(Pick @("ResultCode"))"
        }

        21 {
            $kb = Pick @("UpdateTitle","Title")
            $base.Description = "Windows Update downloaded"
            $base.Details = "Title=$kb; ResultCode=$(Pick @("ResultCode"))"
        }

        6416 {
            $dev = Pick @("DeviceDescription","DeviceName")
            $base.Description = "External device installed"
            $base.Details = "Device=$dev; Class=$(Pick @("ClassName")); HardwareId=$(Pick @("HardwareId"))"
        }

        6419 {
            $dev = Pick @("DeviceDescription","DeviceName")
            $base.Description = "Device disabled"
            $base.Details = "Device=$dev"
        }

        6420 {
            $dev = Pick @("DeviceDescription","DeviceName")
            $base.Description = "Device enabled"
            $base.Details = "Device=$dev"
        }

        # --- Application (MsiInstaller) ---
        11707 {
            $product = Pick @("ProductName","PackageName","UserData:ProductName")
            $base.Description = "Installer: install success"
            $base.Details = "Product=$product"
        }

        11724 {
            $product = Pick @("ProductName","PackageName","UserData:ProductName")
            $err = Pick @("ErrorCode","Status","UserData:ErrorCode")
            $base.Description = "Installer: install/uninstall failed"
            $base.Details = "Product=$product; Error=$err"
        }

        1033 {
            $base.Description = "Installer event (MsiInstaller 1033)"
            $base.Details = "See message for details"
        }

        1034 {
            $base.Description = "Installer installed a product (MsiInstaller 1034)"
            $base.Details = "See message for details"
        }

        default {
            $base.Description = "Event captured"
            $base.Details = "Provider=$prov"
        }
    }

    if ($IncludeMessage) {
        $base["Message"] = $Event.FormatDescription()
    }

    return [pscustomobject]$base
}

# -----------------------------
# Read events
# -----------------------------
Write-Host "Reading events since $StartTime (last $DaysBack day(s))..." -ForegroundColor Cyan

$events = @()

foreach ($q in $LogsToQuery) {
    try {
        $events += Get-WinEvent -FilterHashtable @{
            LogName   = $q.LogName
            Id        = $q.Ids
            StartTime = $StartTime
        } -ErrorAction Stop
    } catch {
        Write-Warning "Could not read log '$($q.LogName)'. Details: $($_.Exception.Message)"
    }
}

$filtered = $events |
    Sort-Object TimeCreated |
    ForEach-Object { New-FilteredEventObject -Event $_ } |
    Where-Object { $_ -ne $null }

# -----------------------------
# Build HTML -> print to PDF
# -----------------------------
$OutDir = Split-Path $OutPdf -Parent
if (-not $OutDir) { $OutDir = $PWD }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

$HtmlPath = Join-Path $OutDir ("filtered_events_report_{0}.html" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

$css = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; }
h1 { margin: 0 0 8px 0; }
.meta { color: #555; margin-bottom: 18px; font-size: 12px; }
h2 { margin-top: 22px; }
.badge { display:inline-block; padding:2px 10px; border-radius: 12px; background:#eee; font-size: 12px; margin-left: 8px; }
table { border-collapse: collapse; width: 100%; margin: 10px 0 18px 0; }
th, td { border: 1px solid #ccc; padding: 8px; vertical-align: top; }
th { background: #f3f3f3; text-align: left; }
.small { color:#555; font-size:12px; }
.wrap { white-space: pre-wrap; }
</style>
"@

$header = @"
<html><head><meta charset="utf-8">$css</head><body>
<h1>Windows Event Log Report</h1>
<div class="meta">
Generated: $(Get-Date)<br/>
Time window: last $DaysBack day(s) (since $StartTime)<br/>
Logs scanned: $((($LogsToQuery | ForEach-Object {$_.LogName}) -join ", "))<br/>
System excluded: $($SystemAccounts -join ", ") + Computer accounts (*$)
</div>
<div class="small">Total incidents flagged: <b>$($filtered.Count)</b></div>
"@

$body = ""

# Ensure we still show empty sections (by clause) even if no matches
$clauseOrder = $ClauseMap.Keys + @("Unmapped")

foreach ($clause in $clauseOrder) {
    $rows = $filtered | Where-Object { $_.Clause -eq $clause }
    $count = @($rows).Count
    $body += "<h2>$clause <span class='badge'>$count</span></h2>"

    if ($count -eq 0) {
        $body += "<div class='small'>No incidents found in this clause for the selected time window.</div>"
        continue
    }

    # Required by you: offender, datetime, event id, description
    $tableObj = $rows | Select-Object TimeCreated, Offender, EventID, Description, LogName, Provider, Details
    $body += ($tableObj | ConvertTo-Html -Fragment)
}

$footer = "</body></html>"

($header + $body + $footer) | Out-File -FilePath $HtmlPath -Encoding UTF8

# Find Edge for headless printing
$EdgePaths = @(
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe"
)
$EdgeExe = $EdgePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $EdgeExe) {
    Write-Warning "Microsoft Edge not found. HTML report saved at: $HtmlPath"
    Write-Warning "Install/repair Edge and print HTML to PDF manually, or run:"
    Write-Warning "msedge --headless --disable-gpu --print-to-pdf=""$OutPdf"" ""file:///$($HtmlPath -replace '\\','/')"""
    return
}

$fileUrl = "file:///" + ($HtmlPath -replace "\\","/")

# Print to PDF
& $EdgeExe --headless --disable-gpu --no-first-run --print-to-pdf="$OutPdf" "$fileUrl" | Out-Null

Write-Host "Done." -ForegroundColor Green
Write-Host "HTML: $HtmlPath"
Write-Host "PDF : $OutPdf"

# Quick on-screen view (latest 30)
$filtered | Select-Object -Last 30 | Format-Table -AutoSize
