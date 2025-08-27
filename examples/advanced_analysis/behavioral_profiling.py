"""
Behavior analysis example
"""

from claude.analysts.behavior_analyst import BehaviorAnalyst

def main():
    analyst = BehaviorAnalyst()
    analyst.analyze_behavior(session_data={})

if __name__ == "__main__":
    main()
