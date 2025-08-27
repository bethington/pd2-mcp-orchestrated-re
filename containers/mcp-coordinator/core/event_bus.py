"""
Event Bus for MCP-Orchestrated Platform
"""

import asyncio
import json
from typing import Dict, List, Callable, Any, Optional
from datetime import datetime
import structlog

logger = structlog.get_logger()

class Event:
    def __init__(self, event_type: str, data: Dict[str, Any], source: str = "unknown"):
        self.event_type = event_type
        self.data = data
        self.source = source
        self.timestamp = datetime.now()
        self.event_id = f"{self.timestamp.timestamp()}_{hash(json.dumps(data, sort_keys=True))}"
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data
        }

class EventBus:
    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = {}
        self.event_queue = asyncio.Queue()
        self.processing = False
        logger.info("Event bus initialized")
        
    async def start(self):
        """Start event processing"""
        if not self.processing:
            self.processing = True
            asyncio.create_task(self._process_events())
            logger.info("Event bus started")
            
    async def stop(self):
        """Stop event processing"""
        self.processing = False
        logger.info("Event bus stopped")
        
    def subscribe(self, event_type: str, callback: Callable[[Event], Any]):
        """Subscribe to events of a specific type"""
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
            
        self.subscribers[event_type].append(callback)
        logger.debug("Subscribed to event", event_type=event_type)
        
    def unsubscribe(self, event_type: str, callback: Callable[[Event], Any]):
        """Unsubscribe from events"""
        if event_type in self.subscribers:
            try:
                self.subscribers[event_type].remove(callback)
                logger.debug("Unsubscribed from event", event_type=event_type)
            except ValueError:
                pass
                
    async def publish(self, event_type: str, data: Dict[str, Any], source: str = "unknown"):
        """Publish an event"""
        event = Event(event_type, data, source)
        await self.event_queue.put(event)
        logger.debug("Published event", event_type=event_type, source=source)
        
    async def _process_events(self):
        """Process events from the queue"""
        while self.processing:
            try:
                # Wait for event with timeout
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                await self._dispatch_event(event)
            except asyncio.TimeoutError:
                # No events to process, continue
                continue
            except Exception as e:
                logger.error("Error processing event", error=str(e))
                
    async def _dispatch_event(self, event: Event):
        """Dispatch event to subscribers"""
        event_type = event.event_type
        
        # Get subscribers for this event type
        subscribers = self.subscribers.get(event_type, [])
        
        # Also notify wildcard subscribers (*)
        subscribers.extend(self.subscribers.get("*", []))
        
        if subscribers:
            logger.debug("Dispatching event", event_type=event_type, subscribers=len(subscribers))
            
            # Call all subscribers
            for callback in subscribers:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(event)
                    else:
                        callback(event)
                except Exception as e:
                    logger.error("Error in event callback", event_type=event_type, error=str(e))
        else:
            logger.debug("No subscribers for event", event_type=event_type)
            
    def get_stats(self) -> Dict[str, Any]:
        """Get event bus statistics"""
        return {
            "processing": self.processing,
            "queue_size": self.event_queue.qsize(),
            "subscriber_types": list(self.subscribers.keys()),
            "total_subscribers": sum(len(subs) for subs in self.subscribers.values())
        }
