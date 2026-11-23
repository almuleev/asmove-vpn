import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1]/'deploy'/filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


setup = module('setup_wizard_test', 'setup.py')
probe = module('probe_test', 'vpn-probe.py')


class SetupTests(unittest.TestCase):
    def test_discovery_derives_ids_and_never_orders_a_server(self):
        api = Mock()
        api.servers.return_value=[{'id':12}]
        api.server.return_value={'id':12,'status':'active','ip':[{'ip':'1.1.1.1','type':'4'}],
                                 'server-plan':{'id':7},'datacenter':{'id':8}}
        catalog={'server-group':[{'id':2}], 'server-plan/2':[{'id':7,'active':True,'enable':True,
                    'period':'day','cost':'0.07','has_params':False}],
                 'datacenter':[{'id':8,'country':'nl','active':True}],
                 'template':[{'id':9,'name':'Ubuntu 24.04','active':True,'ssh-key':True,'server-plan':[7]}],
                 'ssh-key':[{'id':10,'data':'ssh-ed25519 fake-key wizard'}]}
        api.request.side_effect=lambda method,path: catalog[path] if method=='GET' else self.fail('Mutation')
        result=setup.discover(api,'1.1.1.1','ssh-ed25519 fake-key comment',lambda label,rows:rows[0])
        self.assertEqual(result['eu_service_id'],12)
        self.assertEqual(result['candidates'][0]['ssh_key_id'],10)
        self.assertEqual(result['candidates'][0]['plan_id'],7)
        api.order.assert_not_called(); api.delete.assert_not_called()
        for call in api.request.call_args_list: self.assertEqual(call.args[0],'GET')
        catalog['server-plan/2'][0]['cost']='0.50'
        with self.assertRaises(ValueError):
            setup.discover(api,'1.1.1.1','ssh-ed25519 fake-key',lambda label,rows:rows[0])


class ProbeTests(unittest.TestCase):
    def run_probe(self, replies):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory)
            template=directory/'client.json'
            template.write_text(json.dumps({'outbounds':[{'protocol':'vless','settings':{'vnext':[{}]}}]}))
            config=directory/'observer.json'
            config.write_text(json.dumps({'curl':str(directory/'curl'),'xray':str(directory/'xray'),
                'check_urls':['https://first.example/test','https://second.example/test'],
                'nodes':{'EU1':str(template)}}))
            child=MagicMock(); child.__enter__.return_value=child; child.poll.return_value=None
            with patch.object(probe.subprocess,'Popen',return_value=child), patch.object(
                    probe.subprocess,'run',side_effect=[SimpleNamespace(returncode=n) for n in replies]) as request, patch.object(
                    probe.socket,'create_connection',return_value=MagicMock()):
                result=probe.check(config,{'id':'EU1','ip':'1.1.1.1','port':2053})
                return result, request.call_count

    def test_one_successful_vpn_target_is_enough_to_avoid_false_recovery(self):
        result,count=self.run_probe([0,0,1,0])
        self.assertTrue(result['observer_ok']); self.assertTrue(result['vpn_ok'])
        self.assertEqual(result['targets_total'],2); self.assertEqual(count,4)

    def test_both_vpn_targets_fail_but_controls_work(self):
        result,_=self.run_probe([0,0,1,1])
        self.assertTrue(result['observer_ok']); self.assertFalse(result['vpn_ok'])

    def test_failed_direct_control_is_inconclusive(self):
        result,count=self.run_probe([1])
        self.assertFalse(result['observer_ok']); self.assertEqual(count,1)
