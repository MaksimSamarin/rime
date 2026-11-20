"""Deletion of unowned users must revoke native access and report success."""
import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from fastapi import BackgroundTasks


class ManagementUserLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        model = SimpleNamespace(get_current=None,model_validate=Mock(side_effect=self.owner_model))
        self.owner = model
        self.crud = SimpleNamespace(remove_user=Mock(side_effect=self.delete))
        self.native = Mock(side_effect=lambda **values:self.events.append(('revoke',values['dbuser'].username)))
        self.report = Mock(side_effect=lambda **values:self.events.append(('report',values)))
        namespace = {'BackgroundTasks':BackgroundTasks,'Session':object,'UserResponse':object,
                     'Admin':model,'Depends':lambda value:None,'get_db':None,'get_validated_user':None,
                     'crud':self.crud,'xray':SimpleNamespace(operations=SimpleNamespace(remove_user=self.native)),
                     'report':SimpleNamespace(user_deleted=self.report),'logger':SimpleNamespace(info=lambda value:None)}
        tree = ast.parse((Path(__file__).resolve().parents[1]/'app/routers/user.py').read_text())
        function = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='remove_user')
        function.decorator_list = []
        exec(compile(ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[])),'user-route','exec'),namespace)
        self.remove = namespace['remove_user']

    def owner_model(self, owner):
        self.events.append(('owner',owner))
        return SimpleNamespace(username=owner.username)

    def delete(self, db, user):
        self.events.append(('delete',user.username))
        user.deleted = True

    @staticmethod
    def user(owner=None):
        class User:
            id = 7
            username = 'fixture-user'
            deleted = False

            @property
            def admin(self):
                if self.deleted:
                    raise RuntimeError('A deleted owner relationship must not be lazy-loaded')
                return owner

        return User()

    def test_unowned_user_deletion_executes_native_revocation(self):
        bg = BackgroundTasks()
        user = self.user()
        actor = SimpleNamespace(username='sudo')
        response = self.remove(bg,object(),user,actor)
        self.assertEqual(response,{'detail':'User successfully deleted'})
        self.owner.model_validate.assert_not_called()
        asyncio.run(bg())
        self.native.assert_called_once_with(dbuser=user)
        self.report.assert_called_once_with(username='fixture-user',user_admin=None,by=actor)
        self.assertEqual([event[0] for event in self.events],['delete','revoke','report'])

    def test_owner_is_captured_before_committing_deletion(self):
        bg = BackgroundTasks()
        owner = SimpleNamespace(username='owner')
        user = self.user(owner)
        self.remove(bg,object(),user,SimpleNamespace(username='sudo'))
        self.assertEqual([event[0] for event in self.events],['owner','delete'])
        asyncio.run(bg())
        self.assertEqual(self.report.call_args.kwargs['user_admin'].username,'owner')

    def test_failed_deletion_does_not_schedule_false_revocation(self):
        self.crud.remove_user.side_effect = RuntimeError('Synthetic database failure')
        bg = BackgroundTasks()
        with self.assertRaises(RuntimeError):
            self.remove(bg,object(),self.user(),SimpleNamespace(username='sudo'))
        self.assertEqual(bg.tasks,[])
        self.native.assert_not_called()

    def test_invalid_owner_fails_before_deleting_database_user(self):
        self.owner.model_validate.side_effect = ValueError('Synthetic invalid owner')
        with self.assertRaises(ValueError):
            self.remove(BackgroundTasks(),object(),self.user(SimpleNamespace()),SimpleNamespace(username='sudo'))
        self.crud.remove_user.assert_not_called()


if __name__=='__main__':
    unittest.main()
