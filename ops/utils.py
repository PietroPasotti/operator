import logging

from ops.charm import CharmBase

logger = logging.getLogger(__file__)

default_grafana_endpoint = 'grafana-dashboard'
default_prometheus_endpoint = 'metrics-endpoint'
default_loki_endpoint = 'logging'


def add_observability(
        charm: CharmBase,
        grafana: str = None,
        prometheus: str = None,
        loki: str = None,
        grafana_config=None,
        prometheus_config=None,
        loki_config=None,
):
    results = []
    results.append(_add_grafana(charm, grafana, **grafana_config))
    results.append(_add_prometheus(charm, prometheus, **prometheus_config))
    results.append(_add_loki(charm, loki, **loki_config))
    _check_results(results)


def add_grafana(charm: CharmBase, grafana: str = None, config=None):
    results = [_add_grafana(charm, grafana, config)]
    _check_results(results)


def add_loki(charm: CharmBase, loki: str = None, config=None):
    results = [_add_loki(charm, loki, config)]
    _check_results(results)


def add_prometheus(charm: CharmBase, prometheus: str = None, config=None):
    results = [_add_prometheus(charm, prometheus, config)]
    _check_results(results)


def _check_results(results):
    failed = False
    for success, msg in results:
        if not success:
            logger.error(msg)
            failed = True
        elif msg:
            logger.warning(msg)

    if failed:
        raise RuntimeError(results)


def _endpoint_available(charm: CharmBase, role: str, endpoint_name: str):
    if role == 'provider':
        endpoints = charm.meta.provides
    else:  # requirer
        endpoints = charm.meta.requires
    return endpoint_name in endpoints


def _check_installed(lib_path):
    if lib_path == "grafana_k8s.v0.grafana_dashboard":
        try:
            from charms.grafana_k8s.v0.grafana_dashboard import \
                GrafanaDashboardProvider
            return GrafanaDashboardProvider
        except ModuleNotFoundError:
            return False
    if lib_path == "loki_k8s.v0.loki_push_api":
        try:
            from charms.loki_k8s.v0.loki_push_api import LogProxyConsumer
            return LogProxyConsumer
        except ModuleNotFoundError:
            return False
    if lib_path == "prometheus_k8s.v0.prometheus_scrape":
        try:
            from charms.prometheus_k8s.v0.prometheus_scrape import \
                MetricsEndpointProvider
            return MetricsEndpointProvider
        except ModuleNotFoundError:
            return False
    raise NotImplementedError(lib_path)


def _add_grafana(charm: CharmBase, grafana: str = None, **kwargs):
    return _add_lib(charm, grafana, 'grafana_k8s.v0.grafana_dashboard',
                    **kwargs)


def _add_prometheus(charm: CharmBase, prometheus: str = None, **kwargs):
    return _add_lib(charm, prometheus, 'prometheus_k8s.v0.prometheus_scrape',
                    **kwargs)


def _add_loki(charm: CharmBase, prometheus: str = None, **kwargs):
    return _add_lib(charm, prometheus, 'loki_k8s.v0.loki_push_api', **kwargs)


def _add_lib(charm, endpoint, lib, **kwargs):
    if endpoint is None:
        if _endpoint_available(charm, 'provider', default_grafana_endpoint):
            if not (wrapper := _check_installed(lib)):
                return False, f'declared endpoint {default_grafana_endpoint}, ' \
                              f'but no lib. Please run `charmcraft fetch-lib ' \
                              f'charms.{lib}`'
        elif kwargs:
            return False, f'provided args for {endpoint}, but the default' \
                          f'endpoint ({default_grafana_endpoint}) is not available. ' \
                          f'Pass a custom endpoint name or add the default one to metadata.yaml.'
        else:
            return True, ''
    else:
        if not _endpoint_available(charm, 'provider', endpoint):
            return False, f"provider endpoint {endpoint} is not " \
                          f"available in metadata.yaml."
        wrapper = _check_installed(lib)

    wrapper(charm, **(kwargs or {}))
    return True, ''


if __name__ == '__main__':
    # case 1
    # suppose /lib/ is empty.
    class MyCharm(CharmBase):
        META = {}

        def __init__(self, ...):
            add_observability(self)


    # Warning: grafana lib not installed, default grafana endpoint not available
    # Warning: loki lib not installed, default loki endpoint not available
    # Warning: prometheus lib not installed, default prometheus endpoint not available

    # case 1
    # suppose /lib/ is empty.
    class MyCharm(CharmBase):
        META = {}

        def __init__(self, ...):
            add_observability(self, loki='loki_endpoint')


    # Warning: grafana lib not installed, default grafana endpoint not available
    # Error: loki lib not installed, loki endpoint 'loki_endpoint' not found
    # Warning: prometheus lib not installed, default prometheus endpoint not available

    # case 2
    # suppose loki_k8s.v0.loki_push_api is present in /lib/charms
    class MyCharm(CharmBase):
        META = {"requires": {"logging-loki-foo": {'endpoint': 'loki_push_api'}}}

        def __init__(self, ...):
            add_observability(self, loki='loki_endpoint')


    # Warning: grafana lib not installed, default grafana endpoint not available
    # Warning: prometheus lib not installed, default prometheus endpoint not available

    # case 2
    # suppose loki_k8s.v0.loki_push_api is present in /lib/charms
    class MyCharm(CharmBase):
        META = {
            "requires": {"logging-loki-foo": {'endpoint': 'loki_push_api'}},
            "provides": {
                "grafana_dash": {'endpoint': 'grafana_dashboard'},
                "metrics-endpoint": {'endpoint': 'prometheus_scrape'}
            }
        }

        def __init__(self, ...):
            add_observability(self,
                              loki='loki_endpoint',
                              grafana='grafana_dash',
                              loki_config={'log_files': ['/path/to/file.log']},
                              prometheus_config={
                                  'relation_name': "metrics-endpoint",
                                  'jobs': [{"static_configs": [
                                      {"targets": ["*:4080"]}]}]})

        ## all good!
