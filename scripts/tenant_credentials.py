"""Load private centralized YAML credentials without logging their contents."""
from dataclasses import dataclass, field
from pathlib import Path
import re
from urllib.parse import urlparse
from uuid import UUID
import cortex_lookup as api

ROOT = Path(__file__).resolve().parents[1]

class CredentialError(ValueError):
    pass

def load_mapping(path):
    try:
        import yaml
    except ImportError:
        raise CredentialError('Install requirements-rmm.txt to read centralized YAML credentials') from None
    class UniqueLoader(yaml.SafeLoader):
        pass
    def mapping(loader, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in result:
                raise CredentialError('Duplicate credential configuration entry; contents omitted')
            result[key] = loader.construct_object(value_node, deep=deep)
        return result
    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        path = Path(path)
        api.check_secret_permissions(path)
        data = yaml.load(path.read_text(encoding='utf-8-sig'), Loader=UniqueLoader)
        if not isinstance(data, dict) or any(not isinstance(v, dict) for v in data.values()):
            raise CredentialError('Credentials must be a mapping of customer entries')
        return data
    except CredentialError:
        raise
    except Exception:
        # YAML parser messages may contain a source line with a secret.
        raise CredentialError('Cannot read credential YAML; contents omitted') from None

def required(entry, key):
    value = entry.get(key)
    if value is None or not str(value).strip():
        raise CredentialError('Missing required credential field: ' + key)
    return str(value).strip()

def cortex_tenants(path=None, selected=None, allow_shared=False):
    data = load_mapping(path or ROOT/'config/cortex_credentials.yml')
    result = []
    hosts = set()
    for name, entry in data.items():
        if selected and name not in selected:continue
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', str(name)):
            raise CredentialError('Invalid Cortex customer identifier')
        if entry.get('enabled', True) is False:
            continue
        endpoint = required(entry, 'api_url')
        parsed = urlparse(endpoint if '://' in endpoint else 'https://' + endpoint)
        if parsed.path.rstrip('/') not in ('', '/public_api', '/public_api/v1') or parsed.query or parsed.fragment or parsed.username:
            raise CredentialError('Cortex API URL must identify the API host')
        host = api.validate_api_fqdn(parsed.scheme + '://' + (parsed.netloc or ''))
        if not host.endswith('.paloaltonetworks.com'):
            raise CredentialError('Cortex API host must belong to paloaltonetworks.com')
        if host in hosts and not allow_shared:
            raise CredentialError('Duplicate Cortex API host; inspect private customer mapping')
        hosts.add(host)
        kind = str(entry.get('auth_method', 'advanced')).strip().lower()
        kind = {'sha256': 'advanced', 'simple': 'standard'}.get(kind, kind)
        if kind not in ('advanced', 'standard'):
            raise CredentialError('Unsupported Cortex authentication method; value omitted')
        key_id,key=required(entry,'api_key_id'),required(entry,'api_key')
        if not key_id.isdigit() or any(c in key for c in '\r\n'):
            raise CredentialError('Invalid Cortex key format; contents omitted')
        result.append(api.Tenant(str(name), host, key_id, key, kind))
    return result

@dataclass(frozen=True)
class MdeTenant:
    label: str
    tenant_id: str = field(repr=False)
    app_id: str = field(repr=False)
    app_secret: str = field(repr=False)
    graph_app_id: str = field(repr=False)
    graph_app_secret: str = field(repr=False)

def mde_tenants(path=None):
    data = load_mapping(path or ROOT/'config/mde_credentials.yml')
    result = []
    for tenant_id, entry in data.items():
        try:UUID(str(tenant_id))
        except ValueError:
            raise CredentialError('Invalid MDE tenant identifier; value omitted')
        if entry.get('enabled', True) is False:
            continue
        app_id, secret = required(entry, 'app_id'), required(entry, 'app_secret')
        graph_id = str(entry.get('graph_app_id') or app_id).strip()
        graph_secret = str(entry.get('graph_app_secret') or secret).strip()
        if bool(entry.get('graph_app_id')) != bool(entry.get('graph_app_secret')):
            raise CredentialError('Graph override requires both app ID and secret')
        label=required(entry,'label')
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]*',label):raise CredentialError('Invalid MDE customer label')
        result.append(MdeTenant(label, str(tenant_id), app_id, secret, graph_id, graph_secret))
    return result
