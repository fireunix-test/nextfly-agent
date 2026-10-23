"""Verify bounded private reports, update preservation and lock serialization."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch
import report


class ReportTests(unittest.TestCase):
    def state(self):
        return {'run':123, 'attempt':1, 'head':'a'*40, 'merge':'b'*40,
                'expected':['check (ubuntu-latest)','check (windows-latest)'], 'entries':{}}

    def test_report_roundtrip_preserves_platform_failures(self):
        state = self.state()
        for platform in ('ubuntu-latest','windows-latest'):
            name=f'check ({platform})'
            state['entries'][name]={'platform':platform,'passed':False,'failures':[{'stage':'Tests','summary':f'{platform} panic <script> & @user'}]}
        body=report.render(state)
        self.assertEqual(report.unpack(body),state)
        self.assertNotIn('<script>',body)
        self.assertIn('&lt;script&gt;',body)
        self.assertIn('windows-latest panic',body)
        self.assertIn('ubuntu-latest panic',body)
        self.assertEqual(body.count(report.MARKER),1)

    def test_total_report_is_bounded(self):
        import random
        state=self.state()
        for platform in ('ubuntu-latest','windows-latest'):
            state['entries'][f'check ({platform})']={'platform':platform,'passed':False,'failures':[{'stage':'Tests','summary':''.join(random.Random(i).choices('abcdef<&中',k=100000))} for i in range(3)]}
        body=report.render(state)
        self.assertLessEqual(len(body.encode()),60000)
        self.assertIn('已截断',body)
        self.assertEqual(len(report.unpack(body)['entries']),2)

    def test_success_requires_every_job(self):
        state=self.state()
        for name in state['expected']:
            state['entries'][name]={'platform':'ubuntu-latest','passed':True,'failures':[]}
        self.assertIn('✅ 全部通过',report.render(state))
        del state['entries'][state['expected'][0]]
        self.assertNotIn('✅ 全部通过',report.render(state))

    def test_atomic_lock_retries_and_releases_on_exception(self):
        calls=[]
        def api(repo,path,data=None,method=None):
            calls.append((path,method))
            if len(calls)==1:
                raise urllib.error.HTTPError('unused',422,'exists',{},io.BytesIO())
        with patch.dict(os.environ,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',GITHUB_SHA='a'*40), patch.object(report,'api',side_effect=api), patch.object(report.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'private'):
                with report.write_lock(): raise RuntimeError('private')
        self.assertEqual(calls[-1][1],'DELETE')
        self.assertEqual(len(calls),3)

    def test_sequential_jobs_update_one_comment(self):
        state=self.state(); stored=[]; mutations=[]
        def api(repo,path,data=None,method=None):
            if repo==report.BUILDER: return {}
            if path=='': return {'private':True}
            if path=='/pulls/8': return {'state':'open','head':{'sha':state['head'],'repo':{'full_name':report.SOURCE}},'merge_commit_sha':state['merge']}
            mutations.append(method or 'POST'); stored[:]=[{'id':42,'body':data['body']}]
        with tempfile.TemporaryDirectory() as directory, patch.object(report,'api',side_effect=api), patch.object(report,'pages',side_effect=lambda *args: iter(stored)):
            common={'RUNNER_TEMP':directory,'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'c'*40,'PR_NUMBER':'8','SOURCE_SHA':state['merge'],'HEAD_SHA':state['head'],'REPORT_EXPECTED':json.dumps(state['expected']),'BUILD_OUTCOME':'failure'}
            for name,platform in zip(state['expected'],('ubuntu-latest','windows-latest')):
                folder=Path(directory)/'ci-private'; folder.mkdir(exist_ok=True)
                (folder/'summary.json').write_text(json.dumps({'job':name,'source_sha':state['merge'],'head_sha':state['head'],'run_id':'123','attempt':'1','failures':[{'stage':'Tests','summary':platform+' panic'}]}))
                with patch.dict(os.environ,common|{'REPORT_JOB':name,'REPORT_PLATFORM':platform}): report.main()
                self.assertFalse((folder/'summary.json').exists())
        self.assertEqual(mutations,['POST','PATCH'])
        self.assertEqual(len(report.unpack(stored[0]['body'])['entries']),2)
