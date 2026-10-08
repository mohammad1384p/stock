import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import requests

from exir_auth import session_cookies, restore_session_cookies, login
from exir_bot import build_session, apply_replay

BASE = 'https://broker.example'


class SessionTests(unittest.TestCase):
    def test_headers_and_transport(self):
        args = SimpleNamespace(base_url=BASE, cookie=None, app_n='test-app', header=[])
        session = build_session(args, 1)
        req = session.prepare_request(requests.Request('POST', BASE + '/api/v1/order', json={'a': 1}))
        self.assertEqual(req.headers['x-app-n'], 'test-app')
        self.assertEqual(int(req.headers['Content-Length']), len(req.body))
        self.assertIn('zh-CN', req.headers['Accept-Language'])
        self.assertNotIn('sentry-trace', req.headers)

    def test_cookie_roundtrip_scope_expiry_and_override(self):
        session = requests.Session()
        session.cookies.set('cookiesession1', 'saved', domain='broker.example', secure=True)
        session.cookies.set('expired', 'x', domain='broker.example', expires=int(time.time()) - 10)
        session.cookies.set('foreign', 'x', domain='other.example')
        session.cookies.set('JWT-TOKEN', 'secret', domain='broker.example')
        cookies = session_cookies(session, BASE)
        self.assertEqual([c['name'] for c in cookies], ['cookiesession1'])
        restored = requests.Session()
        restore_session_cookies(restored, BASE, cookies)
        self.assertEqual(restored.cookies.get('cookiesession1'), 'saved')
        self.assertTrue(next(iter(restored.cookies)).secure)
        restored.cookies.set('cookiesession1', 'explicit', domain='broker.example')
        restore_session_cookies(restored, BASE, cookies)
        self.assertEqual(restored.cookies.get('cookiesession1'), 'explicit')
        restore_session_cookies(restored, BASE, [{'domain': 'other.example', 'name': 'bad', 'value': 'x'}])
        self.assertIsNone(restored.cookies.get('bad'))

    def test_login_reuses_session_app_header(self):
        session = requests.Session()
        session.headers['x-app-n'] = 'configured-app'
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"authToken":"test-token"}'
        with patch('exir_auth.fetch_captcha', return_value=b'image'), patch('exir_auth.show_captcha'), patch('exir_auth.obtain_captcha', return_value=('1234', 'terminal')), patch.object(session, 'post', return_value=response) as post:
            data = login(session, BASE, 'user', 'password', captcha_url=None, otp=None, captcha_path=None, log=lambda _: None)
        self.assertEqual(data['_appN'], 'configured-app')
        self.assertEqual(post.call_args.kwargs['headers']['x-app-n'], 'configured-app')

    def test_replay_cannot_replace_authenticated_session(self):
        session = requests.Session()
        session.headers['x-app-n'] = 'current'
        apply_replay(session, {'X-App-N': 'stale', 'Cookie': 'JWT-TOKEN=stale', 'accept': 'application/json'}, lambda _: None, preserve_session=True)
        self.assertEqual(session.headers['x-app-n'], 'current')
        self.assertIsNone(session.cookies.get('JWT-TOKEN'))
        self.assertEqual(session.headers['accept'], 'application/json')


if __name__ == '__main__':
    unittest.main()
