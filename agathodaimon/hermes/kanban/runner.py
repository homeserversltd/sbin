"""Run the kanban beat in the Hermes account, not the staff caller's account."""
from __future__ import annotations

import fcntl
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from agathodaimon.hermes.kanban import decision
from agathodaimon._deed import send

NO_ACTION = {'hold-record-state', 'noop', 'skip', 'inspect-running-do-not-steal-pan', 'hold-blocked'}


def _cli(*args):
    home = decision.hermes_home()
    env = {'HOME': str(home.parent), 'HERMES_HOME': str(home),
           'PATH': '/usr/local/bin:/usr/bin:/bin',
           'HERMES_PROFILE': 'default', 'PYTHONDONTWRITEBYTECODE': '1'}
    return subprocess.run([decision.hermes_cli(), '-p', 'default', *args],
                          capture_output=True, text=True, env=env)


def _read_boards(home):
    """Read Hermes board identity markers without starting its writable CLI."""
    root = home / 'kanban' / 'boards'
    items = [('default', root / 'default' / 'board.json')]
    if root.is_dir():
        items.extend((child.name, child / 'board.json') for child in sorted(root.iterdir(), key=lambda p: p.name.lower())
                     if child.is_dir() and child.name != 'default' and (child / 'board.json').is_file())
    found = []
    for slug, marker in items:
        try:
            meta = json.loads(marker.read_text(encoding='utf-8-sig')) if marker.is_file() else {}
        except (OSError, ValueError):
            meta = {}
        if not isinstance(meta, dict) or not meta.get('archived'):
            found.append(slug)
    return found


def _board_available(home, board):
    if not isinstance(board, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', board):
        return False
    root = home / 'kanban' / 'boards' / board
    marker = root / 'board.json'
    database = home / 'kanban.db' if board == 'default' else root / 'kanban.db'
    if not database.is_file() or (board != 'default' and not marker.is_file()):
        return False
    if marker.is_file():
        try:
            meta = json.loads(marker.read_text(encoding='utf-8-sig'))
            if not isinstance(meta, dict) or meta.get('archived'):
                return False
        except (OSError, ValueError):
            return False
    return True


def _failure_count(board, ok):
    path = decision.hermes_home() / 'kanban' / 'beat.sqlite3'
    if ok and not path.exists():
        return
    with sqlite3.connect(path) as con:
        con.execute('create table if not exists beat_failures (board text primary key, consecutive integer not null)')
        previous = con.execute('select consecutive from beat_failures where board = ?', (board,)).fetchone()
        count = 0 if ok else (previous[0] if previous else 0) + 1
        con.execute('insert or replace into beat_failures(board, consecutive) values (?, ?)', (board, count))
    if count == 2:
        send('sbin', 'kanban-beat-repeated-failure', False, target=board,
             signal='kanban-beat-repeated-failure')


def _mentor(board, snapshot):
    path = decision.hermes_home() / 'kanban' / 'beat.sqlite3'
    running = {t['id']: int(t.get('started_at') or t.get('created_at') or 0)
               for t in snapshot['active_tasks'] if t.get('status') == 'running'}
    if not path.exists() and not running:
        return
    with sqlite3.connect(path) as con:
        con.execute('create table if not exists running (board text not null, task_id text not null, started_at integer not null, primary key(board, task_id))')
        prior = dict(con.execute('select task_id, started_at from running where board = ?', (board,)))
        for task_id in prior.keys() - running.keys():
            con.execute('delete from running where board = ? and task_id = ?', (board, task_id))
        for task_id, started in running.items():
            if prior.get(task_id) != started:
                con.execute('insert or replace into running(board, task_id, started_at) values (?, ?, ?)', (board, task_id, started))


def _beat(board, dry):
    snapshot = decision.fetch_assignment_snapshot(board)
    choice = decision.decide_next_management_beat(snapshot, revisit_blocked=True)
    action = choice['action']
    result = {'board': board, 'ok': True, 'actions': [], 'event_through': snapshot['event_through'], 'changed': False}
    if action not in NO_ACTION:
        result['actions'].append({'action': action, 'task_id': choice.get('target_task_id')})
    if dry:
        return result
    _mentor(board, snapshot)
    proc = None
    if action == 'request-asmodeus-assignment-receipt':
        prompt = decision.build_asmodeus_prompt(board, choice.get('target_task_id'))
        proc = _cli('chat', '-q', prompt, '--max-turns', '20')
    elif action == 'reclaim-stale-running':
        proc = _cli('kanban', '--board', board, 'reclaim', str(choice.get('target_task_id')))
    elif action in ('run-native-recompute', 'release-ready-one-child', 'launch-assigned-ready'):
        proc = _cli('kanban', '--board', board, 'dispatch')
    # Revisit is observation only; today's sweep does not grant unblock.
    if proc is not None:
        result['ok'] = proc.returncode == 0
        send('sbin', 'hermes-kanban-beat', result['ok'], target=board,
             signal='hermes-kanban-beat-failed', ref=action)
        after = decision.fetch_assignment_snapshot(board)
        result['event_through'] = max((x for x in (snapshot['event_through'], after['event_through']) if x is not None), default=None)
        result['changed'] = snapshot['event_through'] != after['event_through']
        _mentor(board, after)

    return result


def run(payload):
    home = decision.hermes_home()
    response = {'ok': True, 'boards': [], 'beats': 0, 'event_through': None,
                'mutationPerformed': False, 'firstMissingSignal': 'none'}
    if not home.is_dir() or not (home / 'config.yaml').is_file() or not Path(decision.hermes_cli()).is_file():
        response.update(ok=False, firstMissingSignal='hermes-kanban-hermes-absent')
        return response
    dry = payload.get('dry_run') is True
    board = payload.get('board')
    if board is not None and not _board_available(home, board):
        response.update(ok=False, firstMissingSignal='hermes-kanban-board-list-failed')
        return response
    lock = home / 'kanban' / 'beat.lock'
    handle = None
    try:
        if dry:
            if lock.exists():
                handle = lock.open('rb')
        else:
            lock.parent.mkdir(parents=True, exist_ok=True)
            handle = lock.open('a+b')
        if handle is not None:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                response['firstMissingSignal'] = 'hermes-kanban-busy'
                return response
        if board is not None:
            boards = [board]
        elif dry:
            boards = _read_boards(home)
        else:
            p = _cli('kanban', 'boards', 'list', '--json')
            try:
                listing = json.loads(p.stdout)
                if p.returncode or not isinstance(listing, list):
                    raise ValueError('invalid list')
                boards = [b['slug'] for b in listing if not b.get('archived') and
                          sum(int(v or 0) for k, v in (b.get('counts') or {}).items() if k not in ('done', 'archived')) > 0]
            except (ValueError, KeyError, TypeError):
                response.update(ok=False, firstMissingSignal='hermes-kanban-board-list-failed')
                return response
        for board in boards:
            try:
                if not isinstance(board, str):
                    raise ValueError('invalid board')
                snapshot = decision.fetch_assignment_snapshot(board)
                response['event_through'] = max((x for x in (response['event_through'], snapshot['event_through']) if x is not None), default=None)
                active = snapshot['active_tasks']
                if payload.get('board') is None and (not active or all(t['status'] == 'blocked' for t in active)):
                    continue
                if not dry and (len(active) > 45 or sum(t['status'] == 'running' for t in active) > 10):
                    send('sbin', 'kanban-runaway', False, target=board, signal='kanban-runaway')
                result = _beat(board, dry)
                if not dry:
                    _failure_count(board, result['ok'])
                response['beats'] += 1
                response['event_through'] = max((x for x in (response['event_through'], result.pop('event_through')) if x is not None), default=None)
                response['mutationPerformed'] |= result.pop('changed')
                response['boards'].append(result)
                if not result['ok']:
                    response.update(ok=False, firstMissingSignal='hermes-kanban-beat-failed')
            except (OSError, sqlite3.Error, ValueError, subprocess.SubprocessError):
                if not dry:
                    _failure_count(board, False)
                response['boards'].append({'board': board, 'ok': False, 'actions': []})
                response.update(ok=False, firstMissingSignal='hermes-kanban-beat-failed')
        return response
    finally:
        if handle is not None:
            handle.close()


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin))))
    except Exception:
        print(json.dumps({'ok': False, 'boards': [], 'beats': 0, 'event_through': None,
                          'mutationPerformed': False, 'firstMissingSignal': 'hermes-kanban-beat-failed'}))
