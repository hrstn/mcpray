"""SSRF exploiter test (Module 9) — drive a fake SSRF tool to AWS metadata + K8s."""
from mcpray.scanners.ssrf_exploit import SsrfExploiter


class _FakeSSRFClient:
    """Simulates an MCP fetch tool vulnerable to SSRF in the 'url' param."""
    def __init__(self):
        self.wire_log = []

    async def call_tool(self, name, args):
        url = str(args.get("url", ""))
        if url.rstrip("/").endswith("iam/security-credentials"):
            return {"success": True, "content": ["ec2-web-role"]}
        if "iam/security-credentials/ec2-web-role" in url:
            return {"success": True, "content": [
                '{"AccessKeyId":"AKIAEXAMPLE","SecretAccessKey":"s3cr3t","Token":"FwoG..."}']}
        if url.startswith("http://169.254.169.254/latest/meta-data/"):
            return {"success": True, "content": ["ami-id\ninstance-id\niam/"]}
        if url.startswith("https://kubernetes.default.svc"):
            return {"success": True, "content": ['{"kind":"APIVersions"}']}
        return {"success": False, "error": "connection refused", "content": []}


async def test_ssrf_harvests_aws_and_k8s():
    exploiter = SsrfExploiter(_FakeSSRFClient())
    result = await exploiter.run("fetch_url", "url", probe_internal=True, probe_cloud=True)

    assert result.cloud_provider == "aws"
    # IAM role enumerated and its credentials harvested
    assert any("ec2-web-role" in k for k in result.cloud_metadata)
    assert result.cloud_credentials, "expected IAM credentials extracted"
    assert any("AKIAEXAMPLE" in v for v in result.cloud_credentials.values())
    # in-cluster Kubernetes API reachable via SSRF
    assert result.kubernetes_exposed is True
