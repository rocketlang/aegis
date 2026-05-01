"""
Governed CrewAI example — KavachOS DAN gate + budget guard.

Run with AEGIS running at localhost:4850:

    pip install crewai crewai-kavachos
    python governed_crew.py

Two protection layers:
  1. CrewAIBudgetGuard — pre-flight budget check before crew starts
  2. KavachCrewAICallback — per-tool DAN gate during execution

If AEGIS is unreachable, both fail open (warn only) so the crew still runs.
"""
from crewai import Agent, Crew, Process, Task
from crewai_kavachos import KavachCrewAICallback, governed_kickoff

AEGIS = "http://localhost:4850"

callback = KavachCrewAICallback(base_url=AEGIS, on_block="raise")

researcher = Agent(
    role="Senior Researcher",
    goal="Find accurate information on the given topic",
    backstory="You are an expert researcher with strong fact-checking skills.",
    callbacks=[callback],
    verbose=True,
)

writer = Agent(
    role="Technical Writer",
    goal="Produce a concise, accurate summary",
    backstory="You transform research findings into clear documentation.",
    callbacks=[callback],
    verbose=True,
)

research_task = Task(
    description="Research the current state of AI agent governance frameworks.",
    expected_output="A bullet-point summary of the top 5 frameworks and their enforcement mechanisms.",
    agent=researcher,
)

write_task = Task(
    description="Write a 3-paragraph summary of the research findings.",
    expected_output="A 3-paragraph summary suitable for a technical audience.",
    agent=writer,
    context=[research_task],
)

crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, write_task],
    process=Process.sequential,
    verbose=True,
)

if __name__ == "__main__":
    # governed_kickoff = budget pre-check + crew.kickoff()
    result = governed_kickoff(crew, aegis_url=AEGIS, inputs={})
    print("\n=== Crew Output ===")
    print(result)

    # Tail the audit log
    from crewai_kavachos import AegisClient
    client = AegisClient(base_url=AEGIS)
    audit = client.audit(limit=10)
    print(f"\n=== Last {len(audit.get('records', []))} KAVACH gate decisions ===")
    for rec in audit.get("records", []):
        status = "✅ ALLOW" if rec.get("status") == "allowed" else "❌ BLOCK"
        print(f"  {status}  DAN-{rec.get('level', 0)}  {rec.get('command', '')[:60]}")
