"""
Character monitoring example
"""

from src.game.d2.character_tracker import CharacterTracker

def main():
    tracker = CharacterTracker()
    tracker.monitor_character()

if __name__ == "__main__":
    main()
