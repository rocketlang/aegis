# Fail-closed check for the two adapters (ACP-T1.8). No network: aegis is pointed at a closed port / a stub.
import sys, json, threading, warnings, http.server
import os; _here = os.path.dirname(os.path.abspath(__file__)); sys.path[:0] = [os.path.join(_here, '..'), os.path.join(_here, '..', '..', 'xshieldai-crewai')]
from xshieldai_langchain import KavachGateCallback, KavachGateError
from xshieldai_crewai.gate import CrewAIBudgetGuard

DEAD = "http://127.0.0.1:9"  # discard port: nothing listens
fails = 0
def check(name, cond):
    global fails
    print(("ok   " if cond else "FAIL ") + name); fails += 0 if cond else 1

cb = KavachGateCallback(base_url=DEAD)
try: cb.on_tool_start({"name": "shell"}, "rm -rf /tmp/x"); check("langchain: unreachable refuses by default", False)
except KavachGateError as e: check("langchain: unreachable refuses by default", "fail closed" in e.reason)

with warnings.catch_warnings(record=True):
    warnings.simplefilter("always")
    cb2 = KavachGateCallback(base_url=DEAD, fail_open=True)
    check("langchain: fail_open=True proceeds", cb2.on_tool_start({"name": "shell"}, "ls") is None)

class Stub(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"reason": "no allow field"}).encode())
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 0), Stub); threading.Thread(target=srv.serve_forever, daemon=True).start()
cb3 = KavachGateCallback(base_url=f"http://127.0.0.1:{srv.server_port}")
try: cb3.on_tool_start({"name": "shell"}, "ls"); check("langchain: answer without allow:true is refused", False)
except KavachGateError: check("langchain: answer without allow:true is refused", True)
srv.shutdown()

class Crew:
    started = False
    def kickoff(self, **kw): Crew.started = True; return "ran"
g = CrewAIBudgetGuard(base_url=DEAD)
try: g.kickoff(Crew()); check("crewai: unreachable does not start the crew", False)
except RuntimeError as e: check("crewai: unreachable does not start the crew", "fail closed" in str(e) and not Crew.started)
with warnings.catch_warnings(record=True):
    warnings.simplefilter("always")
    check("crewai: fail_open=True starts the crew", CrewAIBudgetGuard(base_url=DEAD, fail_open=True).kickoff(Crew()) == "ran")
sys.exit(1 if fails else 0)
