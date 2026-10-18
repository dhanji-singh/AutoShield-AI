"""Run inside the gateway container: python mcp_smoke.py. Uses real MCP replays."""
import json
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = 'http://127.0.0.1:8011'
def get(path):
    with urlopen(ROOT + path, timeout=5) as response:
        return json.load(response)
def post(mode, origin=None):
    headers = {'Content-Type': 'application/json', 'X-AutoShield-Local': '1'}
    if origin:
        headers['Origin'] = origin
    req = Request(ROOT + '/api/mcp/runs', json.dumps({'mode': mode}).encode(), headers)
    with urlopen(req, timeout=5) as response:
        return json.load(response)

def main():
    status = get('/api/mcp/status')
    assert not status['active_run'], 'Wait for the current run to finish'
    assert status['armoriq_mode'] == status['semantic_mode'] == 'disabled', 'Smoke tests expect local-only enforcement. Test cloud policy separately.'
    scenarios = [('injection', ['ALLOW', 'BLOCK', 'BLOCK', 'ALLOW']),
                 ('sql', ['SANITIZE', 'BLOCK']), ('rce', ['BLOCK', 'ALLOW']),
                 ('health', ['ALLOW', 'ALLOW', 'ALLOW'])]
    for mode, expected in scenarios:
        run = post(mode)['run_id']
        for _ in range(100):
            events = [e for e in get('/api/mcp/events')['events'] if e.get('run_id') == run]
            if any(e['stage'] in ('run_finished', 'run_error') for e in events) and not get('/api/mcp/status')['active_run']:
                break
            time.sleep(.1)
        assert any(e['stage'] == 'run_finished' for e in events), (mode, events)
        assert [e['decision'] for e in events if e['stage'] == 'decision'] == expected, (mode, events)
        assert all(e['success'] for e in events if e['stage'] == 'result'), (mode, 'Lab execution failed; check fixture-lab')
        print(mode + ': actual MCP decisions and execution results verified')
    try:
        post('health', 'https://evil.invalid')
    except HTTPError as error:
        assert error.code == 403
    else:
        raise AssertionError('Cross-origin POST accepted')
    try:
        urlopen(ROOT + '/transport/')
    except HTTPError as error:
        assert error.code == 401
    else:
        raise AssertionError('Unauthenticated MCP access accepted')
    with urlopen(ROOT + '/api/mcp/stream', timeout=5) as stream:
        assert stream.headers['Content-Type'].startswith('text/event-stream')
        assert stream.readline().startswith(b'id:')
        assert stream.readline().startswith(b'data:')
    print('Access restrictions and SSE verified')

if __name__ == '__main__':
    main()
