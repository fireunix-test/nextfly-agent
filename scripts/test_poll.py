"""Check dispatch deduplication and fail-closed result publication."""
import unittest
from unittest.mock import patch
import poll


class PollTests(unittest.TestCase):
    def test_completion_and_reruns(self):
        sha = 'a' * 40
        for prior, run_status, conclusion, job_count, job_result, expected in [
            ('pending','completed','success',20,'success','success'),
            ('pending','completed','success',19,'success','failure'),
            ('pending','completed','success',20,'skipped','failure'),
            ('pending','completed','failure',20,'success','failure'),
            ('failure','in_progress',None,0,None,'pending'),
            ('success','completed','success',20,'success',None),
        ]:
            def pages(repo,path,key=None):
                if path.endswith('/statuses'):
                    return iter([{'context':poll.CONTEXT,'description':'CI '+sha+' '+prior,
                                  'state':prior,'target_url':'https://github.com/'+poll.BUILDER+'/actions/runs/123'}])
                if '/jobs' in path:
                    return iter([{'name':f'job-{i}','conclusion':job_result} for i in range(job_count)])
                raise AssertionError('Unexpected listing')
            with self.subTest(prior=prior, expected=expected):
                with patch.object(poll,'pages',side_effect=pages), patch.object(poll,'manifest_names',return_value={f'job-{i}' for i in range(20)}), patch.object(poll,'api',return_value={'status':run_status,'conclusion':conclusion}), patch.object(poll,'publish') as publish:
                    poll.reconcile(1,sha,sha)
                    if expected:
                        self.assertEqual(publish.call_args.args[2],expected)
                    else:
                        publish.assert_not_called()

    def test_dispatch_recovery_avoids_duplicate(self):
        sha='a'*40
        import hashlib
        request='poll-'+hashlib.sha256(f'1:{sha}:{sha}'.encode()).hexdigest()[:32]
        def pages(repo,path,key=None):
            if path.endswith('/statuses'): return iter([])
            return iter([{'display_title':'Build '+request,'id':123}])
        with patch.object(poll,'pages',side_effect=pages), patch.object(poll,'api',return_value={'status':'in_progress'}) as api, patch.object(poll,'publish'):
            poll.reconcile(1,sha,sha)
            self.assertFalse(any('/dispatches' in call.args[1] for call in api.call_args_list))


if __name__ == '__main__':
    unittest.main()

class RequiredNamesTests(unittest.TestCase):
    def test_manifest_and_extra_jobs(self):
        import base64
        from checks import manifest_names, successful
        required=manifest_names({'content':base64.b64encode(b'[[bin]]\nname="tracker_http"\n[[bin]]\nname="tracker_udp"').decode()})
        jobs=[{'name':name,'conclusion':'success'} for name in required]
        self.assertTrue(successful(jobs+[{'name':'setup','conclusion':'success'}],required))
        self.assertEqual({j['name'] for j in jobs if j['name'].startswith('fuzz')},
                         {f'fuzz ({i}/7)' for i in range(1, 8)})
        self.assertFalse(successful([j for j in jobs if j['name']!='fuzz (2/7)'],required))
        self.assertFalse(successful(jobs+[jobs[0]],required))
