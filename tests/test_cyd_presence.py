"""SquachWatch HUMAN SENSING <-> RuSense link: the presence registry and the
device-token allowlist.

A SquachWatch board posts its local verdict (POST /api/cyd/presence) and reads
the RuSense verdict (GET /api/cyd/rusense) with a CYD device token. Its vote is
an external, bounded source: it must clamp every field, go stale quickly, and
only count when the board reads MOTION with enough trust.
"""

import os
import re
import time

import pytest

import cyd_node


@pytest.fixture(autouse=True)
def _clean_registry():
    cyd_node._NODES.clear()
    yield
    cyd_node._NODES.clear()


def test_record_presence_clamps_and_names_by_token():
    cyd_node.record_presence(
        {'node': 'spoofed', 'state': 99, 'score': 500, 'rel': -4,
         'presence': 1, 'rssi': 40, 'chan': 'x', 'evil': 'drop me'},
        '10.0.0.9', token_name='kitchen-cyd')
    assert 'spoofed' not in cyd_node._NODES
    p = cyd_node._NODES['kitchen-cyd']['presence']
    assert p['state'] == 4 and p['score'] == 100 and p['rel'] == 0
    assert p['presence'] is True and p['rssi'] == 0 and p['chan'] == 0
    assert 'evil' not in p


def test_vote_needs_motion_and_trust():
    cyd_node.record_presence({'state': 3, 'rel': 90}, None, 'a')
    assert cyd_node.presence_vote() == 0          # POSSIBLE is not a vote
    cyd_node.record_presence({'state': 4, 'rel': 30}, None, 'a')
    assert cyd_node.presence_vote() == 0          # MOTION but untrusted
    cyd_node.record_presence({'state': 4, 'rel': 80}, None, 'a')
    assert cyd_node.presence_vote() == 1


def test_vote_goes_stale():
    cyd_node.record_presence({'state': 4, 'rel': 80}, None, 'a')
    cyd_node._NODES['a']['presence']['ts'] = time.time() - 60
    assert cyd_node.presence_vote() == 0
    s = cyd_node.summarize_node('a')['presence']
    assert s['state'] == 'motion' and s['fresh'] is False


def test_summary_without_presence_is_none():
    cyd_node.record_ingest({'node': 'b', 'beacons': 3}, '10.0.0.2')
    assert cyd_node.summarize_node('b')['presence'] is None


def test_token_allowlist_has_exactly_the_link_routes():
    src = open(os.path.join(os.path.dirname(__file__), '..', 'webapp_modern.py')).read()
    block = re.search(r"cyd_ok = \((.*?)\n        \)", src, re.S).group(1)
    pairs = set(re.findall(r"request\.method == '(\w+)'\s+and path == '([^']+)'", block))
    assert pairs == {
        ('GET', '/api/cyd/status'), ('GET', '/api/cyd/wf'),
        ('POST', '/api/cyd/ingest'), ('POST', '/api/cyd/action'),
        ('GET', '/api/cyd/rusense'), ('POST', '/api/cyd/presence'),
    }
