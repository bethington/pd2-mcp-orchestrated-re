"""
Basic session example for MCP orchestrator
"""

from src.data.models.session import SessionModel

def main():
    session = SessionModel(session_id="example-session")
    print(f"Session started: {session.session_id}")

if __name__ == "__main__":
    main()
