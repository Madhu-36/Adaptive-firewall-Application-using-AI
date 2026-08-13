"""
run.py
======
Main entry point for the Adaptive AI Firewall system.
Launches the FastAPI backend which in turn manages the async pipeline:
PacketEngine -> BehaviorClassifier -> PPOAgent -> NftablesManager.
"""

import uvicorn

if __name__ == "__main__":
    # The application initialization and dependency injection
    # happens inside app.main:app
    uvicorn.run(
        "app.main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=False,
        log_level="info"
    )
