import grpc

from .base import XRayBase
from .exceptions import RelatedError
from .proto.app.proxyman.command import command_pb2, command_pb2_grpc
from .proto.common.protocol import user_pb2
from .types.account import Account
from .types.message import Message, TypedMessage
from .proto.proxy.vless.account_pb2 import Account as VLESSAccountPb2
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

try:
    from .proto.core import config_pb2 as core_config_pb2
except ModuleNotFoundError:
    from .proto import config_pb2 as core_config_pb2


_users_file=descriptor_pb2.FileDescriptorProto(name='rime_inbound_users.proto',package='rime.proxyman',
                                            dependency=[user_pb2.DESCRIPTOR.name],syntax='proto3')
_users_message=_users_file.message_type.add(name='GetInboundUsersResponse')
_users_message.field.add(name='users',number=1,label=3,type=11,type_name='.'+user_pb2.User.DESCRIPTOR.full_name)
_users_descriptor=descriptor_pool.Default().AddSerializedFile(_users_file.SerializeToString())
_UsersResponse=message_factory.GetMessageClass(_users_descriptor.message_types_by_name['GetInboundUsersResponse'])


class Proxyman(XRayBase):
    def get_inbound_users(self, tag: str, timeout: int = None) -> list:
        call=self._channel.unary_unary('/xray.app.proxyman.command.HandlerService/GetInboundUsers',
            request_serializer=command_pb2.RemoveInboundRequest.SerializeToString,
            response_deserializer=_UsersResponse.FromString)
        try:
            response=call(command_pb2.RemoveInboundRequest(tag=tag),timeout=timeout)
        except grpc.RpcError as error:
            if error.code()==grpc.StatusCode.UNIMPLEMENTED:
                raise NotImplementedError('Live user inspection is unavailable') from None
            raise ConnectionError('Live user inspection failed') from None
        result=[]
        for user in response.users:
            if user.account.type!=VLESSAccountPb2.DESCRIPTOR.full_name:
                raise NotImplementedError('Live account type is unsupported')
            value=VLESSAccountPb2.FromString(user.account.value)
            result.append({'email':user.email,'level':user.level,'id':value.id,'flow':value.flow,'encryption':value.encryption})
        return result

    def alter_inbound(self, tag: str, operation: TypedMessage, timeout: int = None) -> bool:
        stub = command_pb2_grpc.HandlerServiceStub(self._channel)
        try:
            stub.AlterInbound(command_pb2.AlterInboundRequest(tag=tag, operation=operation), timeout=timeout)
            return True

        except grpc.RpcError as e:
            raise RelatedError(e)

    def alter_outbound(self, tag: str, operation: TypedMessage, timeout: int = None) -> bool:
        stub = command_pb2_grpc.HandlerServiceStub(self._channel)
        try:
            stub.AlterInbound(command_pb2.AlterOutboundRequest(tag=tag, operation=operation), timeout=timeout)
            return True

        except grpc.RpcError as e:
            raise RelatedError(e)

    def add_inbound_user(self, tag: str, user: Account, timeout: int = None) -> bool:
        return self.alter_inbound(
            tag=tag,
            operation=Message(
                command_pb2.AddUserOperation(
                    user=user_pb2.User(
                        level=user.level,
                        email=user.email,
                        account=user.message
                    )
                )
            ), timeout=timeout)

    def remove_inbound_user(self, tag: str, email: str, timeout: int = None) -> bool:
        return self.alter_inbound(
            tag=tag,
            operation=Message(
                command_pb2.RemoveUserOperation(
                    email=email
                )
            ), timeout=timeout)

    def add_outbound_user(self, tag: str, user: Account, timeout: int = None) -> bool:
        return self.alter_outbound(
            tag=tag,
            operation=Message(
                command_pb2.AddUserOperation(
                    user=user_pb2.User(
                        level=user.level,
                        email=user.email,
                        account=user.message
                    )
                )
            ), timeout=timeout)

    def remove_outbound_user(self, tag: str, email: str, timeout: int = None) -> bool:
        return self.alter_outbound(
            tag=tag,
            operation=Message(
                command_pb2.RemoveUserOperation(
                    email=email
                )
            ), timeout=timeout)

    def add_inbound(self):
        raise NotImplementedError

    def remove_inbound(self):
        raise NotImplementedError

    def add_outbound(self):
        raise NotImplementedError

    def remove_outbound(self):
        raise NotImplementedError
