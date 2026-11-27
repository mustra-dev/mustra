package scarules

// Case is one rule and what Unsupported should say about it. Exported so
// the agent's tests can run the same rules through the evaluator: the
// paths name nothing that exists and the commands are harmless.
type Case struct {
	Kind        string
	Rule        string
	Platform    string
	Unsupported bool
}

// Corpus covers every rule form the engine reads and the ways a rule
// falls outside it.
var Corpus = []Case{
	{"file", "f:/nonexistent/mustra-scarules", "linux", false},
	{"file content", `f:/nonexistent/mustra-scarules -> r:^\s*PermitRootLogin\s+no`, "linux", false},
	{"directory", "d:/nonexistent/mustra-scarules", "linux", false},
	{"directory", "d:/nonexistent/mustra-scarules/*", "linux", false},
	{"directory file", `d:/nonexistent/mustra-scarules -> r:\.conf$`, "linux", false},
	{"directory content", `d:/nonexistent/mustra-scarules -> r:\.conf$ -> r:^\s*install\s+cramfs`, "linux", false},
	{"command", "c:echo mustra -> r:^mustra$", "linux", false},
	{"command", "c:echo mustra", "darwin", false},
	{"process", "p:mustra-scarules-nothing", "", false},
	{"registry", `r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa -> CrashOnAuditFail -> 0`, "windows", false},
	{"registry", `r:HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application`, "windows", false},
	{"negation", `not f:/nonexistent/mustra-scarules -> r:^[\w@.-]+::`, "linux", false},
	{"numeric compare", `f:/nonexistent/mustra-scarules -> n:^\s*PASS_MAX_DAYS\s+(\d+) compare <= 365`, "linux", false},
	{"line conjunction", `c:echo mustra -> r:mus && !r:root && n:(\d+) compare >= 0`, "linux", false},
	{"literal", `r:HKLM\SYSTEM\CurrentControlSet\Services\Spooler -> Start -> 4`, "windows", false},
	{"literal", "f:/nonexistent/mustra-scarules -> !r:^#", "linux", false},

	// Outside the engine.
	{"registry", `r:HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> CrashOnAuditFail -> 0`, "linux", true},
	{"registry", `r:HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> LimitBlankPasswordUse -> 1`, "darwin", true},
	{"registry", `r:HKXX\SOFTWARE\Something -> Value -> 1`, "windows", true},
	{"unknown type", "x:/etc/passwd", "linux", true},
	{"unknown type", "/etc/passwd", "linux", true},
	{"unknown matcher", "f:/nonexistent/mustra-scarules -> weird:thing", "linux", true},
	{"bad regex", "f:/nonexistent/mustra-scarules -> r:(?=lookahead)", "linux", true},
	{"bad regex", "c:echo mustra -> r:a && r:(unclosed", "linux", true},
	{"bad compare", "c:echo mustra -> n:(\\d+) compare about 5", "linux", true},
	{"directory", "d:/nonexistent/mustra-scarules -> weird:name", "linux", true},
	{"directory", `d:/nonexistent/mustra-scarules -> r:\.conf$ -> weird:content`, "linux", true},
	{"negation", "not x:/etc/passwd", "linux", true},
	{"empty", "   ", "linux", true},
}
