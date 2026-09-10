import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('stage_native', Path(__file__).parents[1] / 'stage_native_evidence.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

class NativeEvidenceStageTests(unittest.TestCase):
    def fixture(self):
        policy={'not_before':100,'expires_at':400,'request_event_id':'11'*32,'run_id':'123e4567-e89b-12d3-a456-426614174000','job_id':'job_1','attempt':1,'authority_sha256':'22'*32,'bundle_sha256':'33'*32,'log_sha256':'44'*32,'artifacts':[{'artifact_id':'result','sha256':'55'*32}]}
        config={'schema_version':2,'peer':{'uid':1201,'gid':1201,'allowed_operations':m.OPS},'selectors':{k:{'public_key':str(i)*64,'generation':1} for i,k in enumerate(('ci_event','nip98','manifest'),1)},'nip98_origin':'https://relay.example'}
        plan={'schema_version':1,'validated':True,'request_event_id':policy['request_event_id'],'state':'success','relay_origin':config['nip98_origin'],'keyholder_selectors':config['selectors'],'native_evidence':policy}
        spec={'authority_sha256':policy['authority_sha256'],'bundle_sha256':policy['bundle_sha256']}
        request={'id':policy['request_event_id'],'content':json.dumps({'run_id':policy['run_id'],'job_ids':[policy['job_id']],'attempt':1})}
        return plan,spec,config,request

    def test_valid_plan_and_all_binding_drift_refuse(self):
        plan,spec,config,request=self.fixture()
        self.assertEqual(m.validate_plan(plan,spec,config,request,101)['native_evidence'],plan['native_evidence'])
        mutations=[('request_event_id','99'*32),('run_id','123e4567-e89b-12d3-a456-426614174001'),('job_id','other_job'),('attempt',2),('authority_sha256','99'*32),('bundle_sha256','99'*32),('not_before',1),('expires_at',10000),('artifacts',[]),('artifacts',[{'artifact_id':'../escape','sha256':'55'*32}])]
        for name,value in mutations:
            bad=copy.deepcopy(plan);bad['native_evidence'][name]=value
            with self.subTest(name=name),self.assertRaises(ValueError): m.validate_plan(bad,spec,config,request,101)
        for field,value in [('acceptance',{}),('unrecognized',False)]:
            bad=copy.deepcopy(config);bad[field]=value
            with self.assertRaises(ValueError): m.validate_plan(plan,spec,bad,request,101)
        bad=copy.deepcopy(plan);bad['keyholder_selectors']['nip98']['generation']=2
        with self.assertRaises(ValueError): m.validate_plan(bad,spec,config,request,101)

    def test_recovery_requires_exact_complete_accepted_object_set(self):
        plan,spec,config,request=self.fixture()
        config=m.validate_plan(plan,spec,config,request,101)
        p=plan['native_evidence']
        publications={}
        for index,path in enumerate(sorted(m.paths(p))):
            kind='log' if path.startswith('/ci/logs/') else 'artifact'
            content={k:p[k] for k in ('request_event_id','run_id','job_id','attempt')}
            content.update({'url':config['nip98_origin']+path, 'sha256':path.split('/')[-1]})
            event={'id':str(index+6)*64,'pubkey':config['selectors']['ci_event']['public_key'],'content':json.dumps(content)}
            publications[p['request_event_id']+':'+kind+':job_1:1']={'Accepted':{'signed':{'signed_event':event},'relay_event_id':event['id']}}
        store={'schema_version':1,'publications':publications}
        m.compare_accepted_store(store,config)
        incomplete=copy.deepcopy(store);incomplete['publications'].pop(next(iter(publications)))
        with self.assertRaises(ValueError):m.compare_accepted_store(incomplete,config)
        drift=copy.deepcopy(store);key=next(iter(publications));drift['publications'][key]['Accepted']['relay_event_id']='99'*32
        with self.assertRaises(ValueError):m.compare_accepted_store(drift,config)

    def test_publication_client_and_cas_drift_stop_before_config_writes(self):
        # Mutation guards run before quiescing, writing or restarting.
        for output in [m.SOCKET.encode(),b'']:
            with patch.object(m.os,'open',return_value=7),patch.object(m.os,'close'),patch.object(m.os,'fstat') as metadata,patch.object(m.fcntl,'flock'),patch.object(m,'service_identity',return_value={}),patch.object(m,'run',return_value=output) as run,patch.object(m,'protected',return_value=b'changed'),patch.object(m.os,'replace') as replace:
                metadata.return_value.st_mode=0o100600;metadata.return_value.st_uid=0;metadata.return_value.st_nlink=1
                with self.assertRaises(ValueError):m.apply({'keyholder_binary_sha256':'11'*32},b'old',b'new')
                replace.assert_not_called()
                self.assertEqual(run.call_count,1)

    def test_failed_restart_or_describe_quiesces_both_units(self):
        spec={'keyholder_binary_sha256':'11'*32,'operator':'/operator','authority':'/authority','authority_sha256':'22'*32}
        for fail in ('restart','describe'):
            commands=[]
            def command(argv,timeout=30):
                commands.append(argv)
                if fail == 'restart' and 'restart' in argv: raise ValueError('restart refused')
                if fail == 'describe' and 'describe-keyholder' in argv: raise ValueError('handshake refused')
                if 'show' in argv:return b'inactive\ninactive\n'
                return b''
            with patch.object(m,'run',side_effect=command),patch.object(m,'service_identity',return_value={'InvocationID':'new'}),patch.object(m,'protected',return_value=b'new'):
                with self.assertRaises(ValueError):m.restart_and_verify(spec,{'InvocationID':'old'},b'new')
            self.assertEqual(commands[-2],['/usr/bin/systemctl','stop',m.UNIT,'buzz-ci-keyholder.socket'])
            self.assertIn('show',commands[-1])

    def test_symlink_and_unprotected_parent_are_rejected(self):
        with self.assertRaises(ValueError):m.protected(Path('/tmp'),1024)
        with self.assertRaises(ValueError):m.protected(Path('relative'),1024)

if __name__ == '__main__': unittest.main()
