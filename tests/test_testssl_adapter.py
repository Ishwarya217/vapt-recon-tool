import asyncio
import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.services.testssl.adapter import TestSSLAdapter

async def test_adapter():
    adapter = TestSSLAdapter()
    available = await adapter.check_availability()
    print("testssl.sh Available:", available)
    
    version = await adapter.get_version()
    print("testssl.sh Version:", version)
    
    assert available, "testssl.sh should be available"
    
    print("\nRunning testssl assessment on example.com:443...")
    result, exec_res = await adapter.assess_target("example.com:443")
    print("Execution Success:", exec_res.success)
    print("Execution Time:", round(exec_res.duration_seconds, 2), "s")
    print("STDOUT:", exec_res.stdout[:500])
    print("STDERR:", exec_res.stderr[:500])
    print("Target IP:", result.ip_address)
    print("Certificate Issuer:", result.certificate.issuer if result.certificate else "None")
    print("Certificate Status:", result.certificate.status if result.certificate else "None")
    print("Protocol Support:", result.protocols)
    
    assert result.certificate is not None, "Certificate details should be parsed"

if __name__ == "__main__":
    asyncio.run(test_adapter())
