import dataclasses
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import typing
import datetime
from pathlib import Path
from typing import Optional, Union, Any, Tuple, Iterable, List, Dict, MutableMapping

from _private import yaml
from jujucontext import _JujuContext


class ModelError(Exception):
    """Base class for exceptions raised when interacting with the Model."""


class RelationNotFoundError(ModelError):
    """Raised when querying Juju for a given relation and that relation doesn't exist."""


class SecretNotFoundError(ModelError):
    """Raised when the specified secret does not exist."""


logger = logging.getLogger(__name__)


# relation data is a string key: string value mapping so far as the
# controller is concerned
_RelationDataContent_Raw = Dict[str, str]
_StatusDict = typing.TypedDict('_StatusDict', {'status': str, 'message': str})
_AddressDict = typing.TypedDict(
    '_AddressDict',
    {
        'address': str,  # Juju < 2.9
        'value': str,  # Juju >= 2.9
        'cidr': str,
    },
)
_BindAddressDict = typing.TypedDict(
    '_BindAddressDict', {'interface-name': str, 'addresses': List[_AddressDict]}
)
_NetworkDict = typing.TypedDict(
    '_NetworkDict',
    {
        'bind-addresses': List[_BindAddressDict],
        'ingress-addresses': List[str],
        'egress-subnets': List[str],
    },
)


@dataclasses.dataclass(frozen=True)
class Port:
    """Represents a port opened by :meth:`Unit.open_port` or :meth:`Unit.set_ports`."""

    protocol: typing.Literal['tcp', 'udp', 'icmp']
    """The IP protocol."""

    port: Optional[int]
    """The port number. Will be ``None`` if protocol is ``'icmp'``."""


_ACTION_RESULT_KEY_REGEX = re.compile(r'^[a-z0-9](([a-z0-9-.]+)?[a-z0-9])?$')
MAX_LOG_LINE_LEN = 131071  # Max length of strings to pass to subshell.


class _HookTools:
    """Represents the collection of hook-tools available to the Juju unit to talk to the controller.

    Charm authors should not directly interact with _HookTools, it is a
    private implementation of _ModelBackend.
    """

    def __init__(self, juju_context: _JujuContext = None):
        self._juju_context = juju_context or _JujuContext.from_dict(os.environ)

    def _run(
        self,
        *args: str,
        return_output: bool = False,
        use_json: bool = False,
        input_stream: Optional[str] = None,
    ) -> Union[str, Any, None]:
        kwargs = {
            'stdout': subprocess.PIPE,
            'stderr': subprocess.PIPE,
            'check': True,
            'encoding': 'utf-8',
        }
        if input_stream:
            kwargs.update({'input': input_stream})
        which_cmd = shutil.which(args[0])
        if which_cmd is None:
            raise RuntimeError(f'command not found: {args[0]}')
        args = (which_cmd,) + args[1:]
        if use_json:
            args += ('--format=json',)
        # TODO(benhoyt): all the "type: ignore"s below kinda suck, but I've
        #                been fighting with Pyright for half an hour now...
        try:
            result = subprocess.run(args, **kwargs)  # type: ignore
        except subprocess.CalledProcessError as e:
            raise ModelError(e.stderr) from e
        if return_output:
            if result.stdout is None:  # type: ignore
                return ''
            else:
                text: str = result.stdout  # type: ignore
                if use_json:
                    return json.loads(text)  # type: ignore
                else:
                    return text  # type: ignore

    @staticmethod
    def _is_relation_not_found(model_error: Exception) -> bool:
        return 'relation not found' in str(model_error)

    def relation_ids(self, relation_name: str) -> Tuple[int, ...]:
        """Get the relation IDs for a relation name.

        Args:
            relation_name: name of the relation
        """
        raw_ids = self._run('relation-ids', relation_name, return_output=True, use_json=True)
        return tuple(int(raw_id.split(':')[-1]) for raw_id in typing.cast(Iterable[str], raw_ids))

    def relation_list(self, relation_id: int, app_only: bool = False) -> Optional[Tuple[str, ...]]:
        """Get the list of remote units currently involved in this relation.

        Args:
            relation_id: ID of the relation
            app_only: the hook tool will return only the single remote app name.
        """
        args = ['relation-list', '-r', str(relation_id)]
        if app_only:
            args.append('--app')

        try:
            rel_list = self._run(*args, return_output=True, use_json=True)

            if app_only:
                # hook tool returns single string (or errors out)
                rel_list = [rel_list]

            return tuple(typing.cast(List[str], rel_list))
        except ModelError as e:
            if self._is_relation_not_found(e):
                raise RelationNotFoundError() from e
            if 'option provided but not defined: --app' in str(e):
                # "--app" was introduced to relation-list in Juju 2.8.1, so
                # handle previous versions of Juju gracefully
                return None
            raise

    def relation_get(
        self, relation_id: int, member_name: str, *, app: bool
    ) -> '_RelationDataContent_Raw':
        """Get relation databag contents for this member.

        Args:
            relation_id: ID of the relation to read from
            member_name: name of the relation member whose databag you want to read from.
            app: whether to read from application databag instead of unit databag.
        """

        args = ['relation-get', '-r', str(relation_id), '-', member_name]
        if app:
            if not self._juju_context.version.has_app_data():
                raise RuntimeError(
                    'getting application data is not supported on Juju version '
                    f'{self._juju_context.version}'
                )
            args.append('--app')

        try:
            raw_data_content = self._run(*args, return_output=True, use_json=True)
            return typing.cast('_RelationDataContent_Raw', raw_data_content)
        except ModelError as e:
            if self._is_relation_not_found(e):
                raise RelationNotFoundError() from e
            raise

    def relation_set(self, relation_id: int, key: str, value: str, *, app: bool) -> None:
        """Set relation databag contents.

        Args:
            app: whether to set application databag instead of unit databag.
        """
        args = ['relation-set', '-r', str(relation_id)]
        if app:
            if not self._juju_context.version.has_app_data():
                raise RuntimeError(
                    'setting application data is not supported on Juju version '
                    f'{self._juju_context.version}'
                )
            args.append('--app')
        args.extend(['--file', '-'])

        try:
            content = yaml.safe_dump({key: value})
            self._run(*args, input_stream=content)
        except ModelError as e:
            if self._is_relation_not_found(e):
                raise RelationNotFoundError() from e
            raise

    def config_get(self) -> Dict[str, Union[bool, int, float, str]]:
        """Get the application config."""
        out = self._run('config-get', return_output=True, use_json=True)
        return typing.cast(Dict[str, Union[bool, int, float, str]], out)

    def is_leader(self) -> bool:
        """Obtain the current leadership status for the unit the charm code is executing on.

        This is an atomic check.
        """
        is_leader = self._run('is-leader', return_output=True, use_json=True)
        return typing.cast(bool, is_leader)

    def resource_get(self, resource_name: str) -> str:
        """Get the resource path.

        Args:
            resource_name: Name of the resource to retrieve.
        """
        out = self._run('resource-get', resource_name, return_output=True)
        return typing.cast(str, out).strip()

    def pod_spec_set(self, pod_spec_path: Path, k8s_resources_path: Optional[Path] = None):
        """Set pod spec, optionally providing a path to a k8s resource file.

        Args:
            pod_spec_path: Path to yaml-encoded pod spec file.
            k8s_resources_path: Path to yaml-encoded k8s resources spec file.
        """
        args = ['--file', str(pod_spec_path)]
        if k8s_resources_path:
            args.extend(['--k8s-resources', str(k8s_resources_path)])
        self._run('pod-spec-set', *args)

    def status_get(self, *, app: bool = False) -> '_StatusDict':
        """Get a status of a unit or an application.

        Args:
            app: A boolean indicating whether the status should be retrieved for the application
                 instead of the unit.
        """
        raw_status = self._run(
            'status-get',
            '--include-data',
            f'--application={app}',
            use_json=True,
            return_output=True,
        )

        if app:
            # Application status looks like (in YAML):
            # application-status:
            #   message: 'load: 0.28 0.26 0.26'
            #   status: active
            #   status-data: {}
            #   units:
            #     uo/0:
            #       message: 'load: 0.28 0.26 0.26'
            #       status: active
            #       status-data: {}
            content = typing.cast(Dict[str, Dict[str, str]], raw_status)
            app_status = content['application-status']
            return {'status': app_status['status'], 'message': app_status['message']}
        else:
            # Unit status looks like (in YAML):
            # message: 'load: 0.28 0.26 0.26'
            # status: active
            # status-data: {}
            return typing.cast('_StatusDict', raw_status)

    def status_set(self, status: str, message: str = '', *, app: bool = False) -> None:
        """Set a status of a unit or an application.

        Args:
            status: The status to set.
            message: The message to set in the status.
            app: set the status for the application instead of the unit.
        """
        self._run('status-set', f'--application={app}', status, message)

    def storage_list(self, name: str) -> List[int]:
        """List the storages.

        Args:
            name: Name of the storage
        """

        storages = self._run('storage-list', name, return_output=True, use_json=True)
        storages = typing.cast(List[str], storages)
        return [int(s.split('/')[1]) for s in storages]

    def storage_get(self, storage_full_name: str, key: str = '') -> Union[str, Dict[str, Any]]:
        """Get a storage key.

        Args:
            storage_full_name: Full name of the storage (including the ID), e.g. `mystorage/1`.
            key: Specific key of the storage definition to get.
        """

        out = self._run(
            'storage-get', '-s', storage_full_name, key, return_output=True, use_json=True
        )

        if key:
            # nonempty string: returns value of single attribute
            return typing.cast(str, out)

        # empty string: returns full attribute: value dict
        return typing.cast(Dict[str, Any], out)

    def storage_add(self, name: str, count: int = 1) -> None:
        """Request adding one or multiple storages.

        Args:
            name: name of the storage
            count: Number of instances to request
        """
        self._run('storage-add', f'{name}={count}')

    def action_get(self) -> Dict[str, Any]:
        """Get the currently running action's parameters."""
        out = self._run('action-get', return_output=True, use_json=True)
        return typing.cast(Dict[str, Any], out)

    def action_set(self, results: Dict[str, Any]) -> None:
        """Set results of the currently running action.

        Args:
            results: data to set as action result
        """
        # The Juju action-set hook tool cannot interpret nested dicts, so we use a helper to
        # flatten out any nested dict structures into a dotted notation, and validate keys.
        flat_results = _format_action_result_dict(results)
        self._run('action-set', *[f'{k}={v}' for k, v in flat_results.items()])

    def action_log(self, message: str) -> None:
        """Attach a log to the currently running action

        Args:
             message: Message to log
        """
        self._run('action-log', message)

    def action_fail(self, message: str = '') -> None:
        """Set the currently running action as failed

        Args:
             message: Message to attach to the failure status
        """

        self._run('action-fail', message)

    def application_version_set(self, version: str) -> None:
        """Set the application version

        Args:
             version: version name.
        """
        self._run('application-version-set', '--', version)

    @classmethod
    def log_split(
        cls, message: str, max_len: int = MAX_LOG_LINE_LEN
    ) -> typing.Generator[str, None, None]:
        """Helper to handle log messages that are potentially too long.

        This is a generator that splits a message string into multiple chunks if it is too long
        to safely pass to bash. Will only generate a single entry if the line is not too long.
        """
        if len(message) > max_len:
            yield f'Log string greater than {max_len}. Splitting into multiple chunks: '

        while message:
            yield message[:max_len]
            message = message[max_len:]

    def juju_log(self, level: str, message: str) -> None:
        """Pass a log message on to the juju logger.

        Args:
             level: loglevel
             message: log contents
        """
        for line in self.log_split(message):
            self._run('juju-log', '--log-level', level, '--', line)

    def network_get(self, binding_name: str, relation_id: Optional[int] = None) -> '_NetworkDict':
        """Return network info provided by network-get for a given binding.

        Args:
            binding_name: A name of a binding (relation name or extra-binding name).
            relation_id: An optional relation id to get network info for.
        """
        cmd = ['network-get', binding_name]
        if relation_id is not None:
            cmd.extend(['-r', str(relation_id)])
        try:
            network = self._run(*cmd, return_output=True, use_json=True)
            return typing.cast('_NetworkDict', network)
        except ModelError as e:
            if self._is_relation_not_found(e):
                raise RelationNotFoundError() from e
            raise

    def secret_get(
        self,
        *,
        id: Optional[str] = None,
        label: Optional[str] = None,
        refresh: bool = False,
        peek: bool = False,
    ) -> Dict[str, str]:
        """Get secret contents.

        Args:
            id: secret ID
            label: secret label
            refresh: whether to refresh
            peek: whether to peek
        """

        args: List[str] = []
        if id is not None:
            args.append(id)
        if label is not None:
            args.extend(['--label', label])
        if refresh:
            args.append('--refresh')
        if peek:
            args.append('--peek')
        # IMPORTANT: Don't call shared _run_for_secret method here; we want to
        # be extra sensitive inside secret_get to ensure we never
        # accidentally log or output secrets, even if _run_for_secret changes.
        try:
            result = self._run('secret-get', *args, return_output=True, use_json=True)
        except ModelError as e:
            if 'not found' in str(e):
                raise SecretNotFoundError() from e
            raise
        return typing.cast(Dict[str, str], result)

    def _run_for_secret(
        self, *args: str, return_output: bool = False, use_json: bool = False
    ) -> Union[str, Any, None]:
        try:
            return self._run(*args, return_output=return_output, use_json=use_json)
        except ModelError as e:
            if 'not found' in str(e):
                raise SecretNotFoundError() from e
            raise

    def secret_info_get(
        self, *, id: Optional[str] = None, label: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get secret info.

        Format is a dict of {secret_id: {info}}

        Args:
            id: secret ID
            label: secret label
        """

        args: List[str] = []
        if id is not None:
            args.append(id)
        elif label is not None:  # elif because Juju secret-info-get doesn't allow id and label
            args.extend(['--label', label])
        result = self._run_for_secret('secret-info-get', *args, return_output=True, use_json=True)
        info_dicts = typing.cast(Dict[str, Any], result)
        return info_dicts

    def secret_set(
        self,
        id: str,
        *,
        content: Optional[Dict[str, str]] = None,
        label: Optional[str] = None,
        description: Optional[str] = None,
        expire: Optional[datetime.datetime] = None,
        rotate: Optional[str] = None,
    ):
        """Set secret contents and metadata.

        Args:
            id: secret ID
            content: secret content
            label: secret label
            description: secret description
            expire: secret expiration time
            rotate: secret rotation policy
        """
        args = [id]
        if label is not None:
            args.extend(['--label', label])
        if description is not None:
            args.extend(['--description', description])
        if expire is not None:
            args.extend(['--expire', expire.isoformat()])
        if rotate is not None:
            args += ['--rotate', rotate]
        with tempfile.TemporaryDirectory() as tmp:
            # The content is None or has already been validated with Secret._validate_content
            for k, v in (content or {}).items():
                with open(f'{tmp}/{k}', mode='w', encoding='utf-8') as f:
                    f.write(v)
                args.append(f'{k}#file={tmp}/{k}')
            self._run_for_secret('secret-set', *args)

    def secret_add(
        self,
        content: Dict[str, str],
        *,
        label: Optional[str] = None,
        description: Optional[str] = None,
        expire: Optional[datetime.datetime] = None,
        rotate: Optional[str] = None,
        owner: Optional[str] = None,
    ) -> str:
        """Create a secret.

        Args:
            content: secret content
            label: secret label
            description: secret description
            expire: secret expiration time
            rotate: secret rotation policy
            owner: secret owner
        """
        args: List[str] = []
        if label is not None:
            args.extend(['--label', label])
        if description is not None:
            args.extend(['--description', description])
        if expire is not None:
            args.extend(['--expire', expire.isoformat()])
        if rotate is not None:
            args += ['--rotate', rotate]
        if owner is not None:
            args += ['--owner', owner]
        with tempfile.TemporaryDirectory() as tmp:
            # The content has already been validated with Secret._validate_content
            for k, v in content.items():
                with open(f'{tmp}/{k}', mode='w', encoding='utf-8') as f:
                    f.write(v)
                args.append(f'{k}#file={tmp}/{k}')
            result = self._run('secret-add', *args, return_output=True)
        secret_id = typing.cast(str, result)
        return secret_id.strip()

    def secret_grant(self, id: str, relation_id: int, *, unit: Optional[str] = None):
        """Grant a secret.

        Args:
            id: secret ID
            relation_id: ID of the relation over which to grant
            unit: grantee unit
        """
        args = [id, '--relation', str(relation_id)]
        if unit is not None:
            args += ['--unit', str(unit)]
        self._run_for_secret('secret-grant', *args)

    def secret_revoke(self, id: str, relation_id: int, *, unit: Optional[str] = None):
        """Revoke a secret.

        Args:
            id: secret ID
            relation_id: ID of the relation over which to revoke
            unit: grantee unit
        """
        args = [id, '--relation', str(relation_id)]
        if unit is not None:
            args += ['--unit', str(unit)]
        self._run_for_secret('secret-revoke', *args)

    def secret_remove(self, id: str, *, revision: Optional[int] = None):
        """Remove a secret.

        Args:
            id: secret ID
            revision: single revision to remove. If omitted, will remove all
                revisions and effectively delete the secret.
        """
        args = [id]
        if revision is not None:
            args.extend(['--revision', str(revision)])
        self._run_for_secret('secret-remove', *args)

    def open_port(self, protocol: str, port: Optional[int] = None):
        """Open a port.

        Args:
            protocol: port protocol. Currently supported: 'tcp', 'udp', 'icmp'
            port: port number to be opened. Required for TCP and UDP; not allowed
                for ICMP.
        """
        arg = f'{port}/{protocol}' if port is not None else protocol
        self._run('open-port', arg)

    def close_port(self, protocol: str, port: Optional[int] = None):
        """Close a port.

        Args:
            protocol: port protocol. Currently supported: 'tcp', 'udp', 'icmp'
            port: port number to be opened. Required for TCP and UDP; not allowed
                for ICMP.
        """
        arg = f'{port}/{protocol}' if port is not None else protocol
        self._run('close-port', arg)

    def opened_ports(self) -> typing.Set[Port]:
        """Get the set of opened ports on this unit."""

        # We could use "opened-ports --format=json", but it's not really
        # structured; it's just an array of strings which are the lines of the
        # text output, like ["icmp","8081/udp"]. So it's probably just as
        # likely to change as the text output, and doesn't seem any better.
        output = typing.cast(str, self._run('opened-ports', return_output=True))
        ports: typing.Set[Port] = set()
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            port = self._parse_opened_port(line)
            if port is not None:
                ports.add(port)
        return ports

    @classmethod
    def _parse_opened_port(cls, port_str: str) -> Optional[Port]:
        if port_str == 'icmp':
            return Port('icmp', None)
        port_range, slash, protocol = port_str.partition('/')
        if not slash or protocol not in ['tcp', 'udp']:
            logger.warning('Unexpected opened-ports protocol: %s', port_str)
            return None
        port, hyphen, _ = port_range.partition('-')
        if hyphen:
            logger.warning('Ignoring opened-ports port range: %s', port_str)
        protocol_lit = typing.cast(typing.Literal['tcp', 'udp'], protocol)
        return Port(protocol_lit, int(port))

    def reboot(self, now: bool = False):
        """Reboot this unit.

        Args:
            now: reboot it now
        """
        if now:
            self._run('juju-reboot', '--now')
            # Juju will kill the Charm process, and in testing no code after
            # this point would execute. However, we want to guarantee that for
            # Charmers, so we force that to be the case.
            sys.exit()
        else:
            self._run('juju-reboot')

    def credential_get(self) -> Dict[str, Any]:
        """Access cloud credentials by running the credential-get hook tool.

        Returns the cloud specification used by the model.
        """
        result = self._run('credential-get', return_output=True, use_json=True)
        return typing.cast(Dict[str, Any], result)

    def goal_state(self) -> Dict[str, Dict[str, Any]]:
        """Run the goal-state hook tool."""
        goal_state = self._run('goal-state', return_output=True, use_json=True)
        return typing.cast(Dict[str, Dict[str, Any]], goal_state)


def _format_action_result_dict(
    input: Dict[str, Any],
    parent_key: Optional[str] = None,
    output: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Turn a nested dictionary into a flattened dictionary, using '.' as a key seperator.

    This is used to allow nested dictionaries to be translated into the dotted format required by
    the Juju `action-set` hook tool in order to set nested data on an action.

    Additionally, this method performs some validation on keys to ensure they only use permitted
    characters.

    Example::

        >>> test_dict = {'a': {'b': 1, 'c': 2}}
        >>> _format_action_result_dict(test_dict)
        {'a.b': 1, 'a.c': 2}

    Arguments:
        input: The dictionary to flatten
        parent_key: The string to prepend to dictionary's keys
        output: The current dictionary to be returned, which may or may not yet be completely flat

    Returns:
        A flattened dictionary with validated keys

    Raises:
        ValueError: if the dict is passed with a mix of dotted/non-dotted keys that expand out to
            result in duplicate keys. For example: {'a': {'b': 1}, 'a.b': 2}. Also raised if a dict
            is passed with a key that fails to meet the format requirements.
    """
    output_: Dict[str, str] = output or {}

    for key, value in input.items():
        # Ensure the key is of a valid format, and raise a ValueError if not
        if not isinstance(key, str):
            # technically a type error, but for consistency with the
            # other exceptions raised on key validation...
            raise ValueError(f'invalid key {key!r}; must be a string')
        if not _ACTION_RESULT_KEY_REGEX.match(key):
            raise ValueError(
                f"key {key!r} is invalid: must be similar to 'key', 'some-key2', or 'some.key'"
            )

        if parent_key:
            key = f'{parent_key}.{key}'

        if isinstance(value, MutableMapping):
            value = typing.cast(Dict[str, Any], value)
            output_ = _format_action_result_dict(value, key, output_)
        elif key in output_:
            raise ValueError(
                f"duplicate key detected in dictionary passed to 'action-set': {key!r}"
            )
        else:
            output_[key] = value

    return output_
