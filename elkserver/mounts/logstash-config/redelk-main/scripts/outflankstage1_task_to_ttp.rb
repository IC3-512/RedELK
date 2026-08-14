#
# Part of RedELK
#
# Maps an Outflank Stage1 task name to the MITRE ATT&CK technique(s) it performs.
#
# Cobalt Strike writes the techniques it maps a task to into the beacon log itself
# ("[task] <T1113, T1093> Tasked beacon to take screenshot") and 51-filter-c2-cobaltstrike parses
# them out. Outflank records nothing of the kind. That was checked against the product rather than
# assumed: its task table has fifteen columns
#
#   uid, implant_uid, name, out_name, arguments, run_arguments, out_arguments, binary_content,
#   binary_content_name, response, response_timestamp, response_bytes_total, state, timestamp,
#   operator
#
# and no column in any of its three databases matches technique|mitre|attack|ttp. Neither does
# anything under its api/ directory. So without this table an engagement run from Outflank produces
# no ATT&CK data at all: threat.technique.id is never set, enrich_ttp only ever resolves ids that
# already exist, and the Navigator layer it exports comes out empty.
#
# A static table is honest here because the vocabulary is small and closed - 59 commands in
# lib/outflank_stage1/outflank_stage1/task/tasks - and each one does a fixed thing.
#
# Tasks absent from the table are left untagged deliberately. An analyst reading a Navigator layer
# is reasoning about what actually happened on an engagement, and a plausible-but-wrong technique is
# worse than a gap: the gap is visible and the wrong one is not. So navigation (cd, pwd, mkdir, mv,
# cp), implant housekeeping (sleep, delay, exit, config, help, task, note, fullcheckin) and the
# commands whose technique depends entirely on an argument that is not parsed here (hooks, plist,
# kill, getprivs) are all absent on purpose.
#
# Author: RedELK contributors
#

TASK_TECHNIQUES = {
  # -- discovery ---------------------------------------------------------------------------------
  "ls"                => ["T1083"],              # File and Directory Discovery
  "drives"            => ["T1082"],              # System Information Discovery
  "env"               => ["T1082"],              # System Information Discovery
  "uptime"            => ["T1082"],              # System Information Discovery
  "dnsname"           => ["T1016"],              # System Network Configuration Discovery
  "domainname"        => ["T1016"],              # System Network Configuration Discovery
  "ip"                => ["T1016"],              # System Network Configuration Discovery
  "ps"                => ["T1057"],              # Process Discovery
  "psgrep"            => ["T1057"],              # Process Discovery
  "psx"               => ["T1057"],              # Process Discovery
  "psxx"              => ["T1057"],              # Process Discovery
  "whoami"            => ["T1033"],              # System Owner/User Discovery
  "list_apps"         => ["T1518"],              # Software Discovery
  "list_entitlements" => ["T1518"],              # Software Discovery
  "check_tcc"         => ["T1518.001"],          # Security Software Discovery (macOS TCC)

  # -- collection and exfiltration ---------------------------------------------------------------
  "cat"               => ["T1005"],              # Data from Local System
  "screenshot"        => ["T1113"],              # Screen Capture
  # Two techniques because the task genuinely does two things: it reads the file off the host and
  # sends it back over the C2 channel.
  "download"          => ["T1005", "T1041"],     # Data from Local System, Exfil Over C2 Channel

  # -- ingress -----------------------------------------------------------------------------------
  "upload"            => ["T1105"],              # Ingress Tool Transfer

  # -- execution ---------------------------------------------------------------------------------
  "exec_command"      => ["T1059"],              # Command and Scripting Interpreter
  "exec_process"      => ["T1106"],              # Native API
  "exec_dotnet"       => ["T1620"],              # Reflective Code Loading
  "exec_bof"          => ["T1620"],              # Reflective Code Loading
  "exec_bof_async"    => ["T1620"],              # Reflective Code Loading
  "exec_shellcode"    => ["T1055"],              # Process Injection
  "exec_jxa"          => ["T1059.002"],          # Command and Scripting Interpreter: AppleScript
  "load_library"      => ["T1129"],              # Shared Modules

  # -- privilege escalation, tokens --------------------------------------------------------------
  "getsystem"         => ["T1134.001"],          # Token Impersonation/Theft
  "steal_token"       => ["T1134.001"],          # Token Impersonation/Theft
  "make_token"        => ["T1134.003"],          # Make and Impersonate Token
  "spawnas"           => ["T1134.002"],          # Create Process with Token
  "rev2self"          => ["T1134"],              # Access Token Manipulation

  # -- defense evasion ---------------------------------------------------------------------------
  "timestomp"         => ["T1070.006"],          # Indicator Removal: Timestomp
  "rm"                => ["T1070.004"],          # Indicator Removal: File Deletion
  "rmdir"             => ["T1070.004"],          # Indicator Removal: File Deletion

  # -- registry ----------------------------------------------------------------------------------
  # reg takes the operation as an argument, so both the read and the write technique apply.
  "reg"               => ["T1012", "T1112"],     # Query Registry, Modify Registry

  # -- command and control -----------------------------------------------------------------------
  "socks"             => ["T1090"],              # Proxy
  "portforward"       => ["T1090"],              # Proxy
  "rportforward"      => ["T1090"],              # Proxy
  "link"              => ["T1090.001"],          # Internal Proxy
  "unlink"            => ["T1090.001"],          # Internal Proxy
  "burn"              => ["T1008"]               # Fallback Channels
}.freeze

def register(params); end

def filter(event)
  task = event.get("[implant][task]")
  return [event] unless task.is_a?(String)

  # Never overwrite what is already there. Nothing in the Stage1 filter sets this today, but an
  # operator-written <T1234> marker or a future parser is more specific than a lookup on the task
  # name, and an enrichment must not undo something better.
  return [event] unless event.get("[threat][technique][id]").nil?

  ids = TASK_TECHNIQUES[task.strip.downcase]
  return [event] if ids.nil?

  # dup, because the table is frozen and shared across every event on this pipeline; handing out
  # the same array would let one event's later mutation reach all of them.
  event.set("[threat][technique][id]", ids.dup)
  event.set("[threat][framework]", "MITRE ATT&CK")
  [event]
end

# These run on every `logstash -t`, which means on every install rather than only in CI.

test "a task maps to its technique" do
  in_event { { "implant" => { "task" => "screenshot" } } }
  expect("it is tagged with Screen Capture") do |events|
    events.first.get("[threat][technique][id]") == ["T1113"] &&
      events.first.get("[threat][framework]") == "MITRE ATT&CK"
  end
end

test "a task that does two things gets both techniques" do
  in_event { { "implant" => { "task" => "download" } } }
  expect("collection and exfiltration") do |events|
    events.first.get("[threat][technique][id]") == %w[T1005 T1041]
  end
end

test "an unmapped task is left alone" do
  in_event { { "implant" => { "task" => "cd" } } }
  expect("no technique invented for it") do |events|
    events.first.get("[threat][technique][id]").nil?
  end
end

test "a line with no task at all is left alone" do
  in_event { { "c2" => { "message" => "INIT stage1Uid:AAAA" } } }
  expect("nothing is set") do |events|
    events.first.get("[threat][technique][id]").nil?
  end
end

test "an existing technique id is not overwritten" do
  in_event { { "implant" => { "task" => "ls" }, "threat" => { "technique" => { "id" => ["T9999"] } } } }
  expect("the more specific value survives") do |events|
    events.first.get("[threat][technique][id]") == ["T9999"]
  end
end
