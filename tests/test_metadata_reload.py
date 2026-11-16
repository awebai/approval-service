"""A running grader installs verified reviewed pins without weakening policy."""

import copy
import hashlib
import json
from datetime import timedelta

import pytest
from test_metadata_cache import manifest
from vendor import NOW, Vendor, signed_metadata

from approval_service.grading import EnrollmentGrading
from approval_service.verify import Refused


def renew(transport,config,entries):
    newer=signed_metadata(entries,sequence=2,next_update=NOW+timedelta(days=6))
    config=copy.deepcopy(config)
    config['minimum_sequence']=2
    config['artifacts']['blob']['url']=transport[0]+'/2/blob'
    config['artifacts']['blob']['sha256']=hashlib.sha256(newer['blob']).hexdigest()
    transport[1]['/2/blob']=newer['blob']
    return config


def test_verified_manifest_reloads_after_startup_without_a_second_registration(transport,tmp_path):
    vendor=Vendor(); config=manifest(transport,entries=[vendor.entry()])
    path=tmp_path/'pin.json';path.write_text(json.dumps(config))
    grading=EnrollmentGrading.load(mode='hardware',cache_dir=tmp_path/'cache',manifest_path=path,now=NOW)
    response,challenge=vendor.registration()
    later=NOW+timedelta(days=2)
    with pytest.raises(Refused,match='snapshot_expired'):
        grading.check(response,expected_challenge=challenge,origin='https://approval.example.test',rp_id='approval.example.test',now=later)
    path.write_text(json.dumps(renew(transport,config,[vendor.entry()])))
    assert grading.refresh(now=later) is True
    assert grading.status(now=later)['metadata']['sequence']==2
    assert grading.check(response,expected_challenge=challenge,origin='https://approval.example.test',rp_id='approval.example.test',now=later).grade=='certified_hardware'
    count=len(transport[2])
    assert grading.refresh(now=later) is False
    assert len(transport[2])==count


def test_bad_replacement_keeps_only_the_still_valid_old_snapshot(transport,tmp_path):
    vendor=Vendor();config=manifest(transport,entries=[vendor.entry()]);path=tmp_path/'pin.json';path.write_text(json.dumps(config))
    grading=EnrollmentGrading.load(mode='hardware',cache_dir=tmp_path/'cache',manifest_path=path,now=NOW)
    bad=renew(transport,config,[vendor.entry()]);bad['artifacts']['blob']['sha256']='0'*64;path.write_text(json.dumps(bad))
    with pytest.raises(ValueError):grading.refresh(now=NOW)
    assert grading.status(now=NOW)['metadata']['sequence']==1
    assert grading.status(now=NOW)['metadata']['reload_error']=='metadata_reload_failed'
    response,challenge=vendor.registration()
    assert grading.check(response,expected_challenge=challenge,origin='https://approval.example.test',rp_id='approval.example.test',now=NOW).grade=='certified_hardware'
    with pytest.raises(Refused,match='snapshot_expired'):
        grading.check(response,expected_challenge=challenge,origin='https://approval.example.test',rp_id='approval.example.test',now=NOW+timedelta(days=2))
