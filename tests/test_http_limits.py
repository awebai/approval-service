"""Real ASGI requests: per-IP work bounds precede parsing and admission."""

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair
from awid.registry import RegistryClient
from approval_service.http import create_app
from approval_service.grading import EnrollmentGrading
from approval_service.public import PublicReader


@pytest.mark.asyncio
async def test_ip_budget_cannot_be_reset_by_descriptors_paths_or_forwarded_headers():
    app=create_app(None,public=PublicReader(RegistryClient('http://127.0.0.1:1')),
        origin='https://approval.example.test',rp_id='approval.example.test',
        grading=EnrollmentGrading('passkey_only',None),requests_per_ip=3)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('192.0.2.1',1234)),base_url='https://approval.example.test') as caller:
        for n in range(3):
            _,pub=generate_keypair()
            r=await caller.post('/v1/requests/submit',json={'requester':{'key':did_from_public_key(pub)}},headers={'X-Forwarded-For':f'198.51.100.{n+1}'})
            assert r.status_code==400 and r.json()['error']['code']=='body_invalid'
        r=await caller.post('/v1/enrollments/start',content=b'not JSON',headers={'X-Forwarded-For':'203.0.113.8'})
        assert r.status_code==429 and r.json()['error']['code']=='rate_limited'
        assert r.headers['cache-control']=='no-store' and 'content-security-policy' in r.headers
        assert (await caller.get('/')).status_code==200
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('192.0.2.2',1234)),base_url='https://approval.example.test') as other:
        r=await other.post('/v1/requests/submit',content=b'not JSON')
        assert r.status_code==400 and r.json()['error']['code']=='body_invalid'


@pytest.mark.asyncio
async def test_missing_peer_has_a_shared_finite_budget():
    app=create_app(None,public=None,origin='https://approval.example.test',rp_id='approval.example.test',grading=EnrollmentGrading('passkey_only',None),requests_per_ip=1)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=None),base_url='https://approval.example.test') as caller:
        assert (await caller.get('/v1/missing')).status_code==404
        assert (await caller.get('/v1/another')).status_code==429
