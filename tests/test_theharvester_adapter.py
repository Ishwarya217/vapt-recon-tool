import asyncio
import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.services.theharvester.adapter import TheHarvesterAdapter

async def test_adapter():
    adapter = TheHarvesterAdapter()
    available = await adapter.check_availability()
    print("theHarvester Available:", available)
    
    version = await adapter.get_version()
    print("theHarvester Version:", version)
    
    assert available, "theHarvester should be available"
    
    print("\nRunning discovery on owasp.org...")
    batch, result = await adapter.discover("owasp.org", sources=["hackertarget"])
    print("Execution Success:", result.success)
    print("STDOUT:", result.stdout)
    print("STDERR:", result.stderr)
    print("Total Discovered Hostnames:", batch.total_discovered)
    print("Sources Used:", batch.sources_used)
    print("Sample Hostnames:", [item.hostname for item in batch.items[:5]])
    
    assert batch.total_discovered > 0, "Should discover hostnames for owasp.org"

if __name__ == "__main__":
    asyncio.run(test_adapter())
