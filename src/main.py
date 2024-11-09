import logging
import os
import secrets
import tempfile
import time
import requests
from dataclasses import dataclass, field
import tomllib
from typing import overload, Literal, Optional

logging.basicConfig(format='[%(asctime)s] [%(levelname)s] %(message)s', level=logging.DEBUG)
logger = logging.getLogger()

logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)


@dataclass
class Config:
    local_url: str
    local_username: str
    local_password: str

    remote_url: str
    remote_username: str
    remote_password: str

    interval: int = 60 * 60 * 24  # 间隔时间
    ssl_verify: bool = True
    sync_domains: list[str] = field(default_factory=list)


class NPMRequester:
    def __init__(self, base_url: str, username: str, password: str, config: Config):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.config = config
        self.session = requests.Session()
        self._token: Optional[str] = None
        self.temp_dir = tempfile.TemporaryDirectory()

    def authed_headers(self):
        self.make_authed()
        return {
            'Authorization': 'Bearer ' + self._token
        }

    @overload
    def req(
            self,
            method: str,
            url: str,
            *,
            payload: dict = None,
            files=None,
            to_json: Literal[True] = True,
            resp_text_log=True,
            auth=True
    ) -> dict | list:
        ...

    @overload
    def req(
            self,
            method: str,
            url: str,
            *,
            payload: dict = None,
            files=None,
            to_json: Literal[False] = False,
            resp_text_log=True,
            auth=True
    ) -> requests.Response:
        ...

    def req(
            self,
            method: str,
            url: str,
            *,
            payload: dict = None,
            files=None,
            to_json=True,
            resp_text_log=True,
            auth=True
    ) -> dict | list | requests.Response:
        url = self.base_url + url
        logger.debug(f'Req: [{method.upper()} {url}], json: {payload}')
        resp = self.session.request(
            method,
            url,
            json=payload,
            headers=self.authed_headers() if auth else None,
            files=files,
            timeout=15,
            verify=self.config.ssl_verify
        )
        msg = f'Res: [{method.upper()} {resp.status_code} {url}]'
        if resp_text_log:
            msg += f', text: {resp.text}]'
        logger.debug(msg)
        resp.raise_for_status()
        if to_json:
            return resp.json()
        else:
            return resp

    def make_authed(self):
        if self._token is None:
            self._token = self.req_login(self.username, self.password)['token']

    def req_login(self, username: str, password: str) -> dict:
        payload = {
            'identity': username,
            'secret': password
        }
        return self.req('POST', '/api/tokens', payload=payload, auth=False)

    def req_cert_list(self) -> list:
        return self.req('GET', '/api/nginx/certificates?expand=owner')

    def req_cert_info(self, cert_id: int):
        return self.req('GET', f'/api/nginx/certificates/{cert_id}')

    def req_download_cert(self, cert_id: id) -> requests.Response:
        url = f'/api/nginx/certificates/{cert_id}/download'
        return self.req('GET', url, to_json=False, resp_text_log=False)

    def req_add_cert(self, nice_name: str) -> dict:
        """添加证书"""
        payload = {
            'nice_name': nice_name,
            'provider': 'other'
        }
        return self.req('POST', '/api/nginx/certificates', payload=payload)

    def req_upload_cert(
            self,
            cert_id: int,
            certificate: bytes,
            certificate_key: bytes,
            intermediate_certificate: bytes
    ) -> dict:
        """上传证书内容"""
        url = f'/api/nginx/certificates/{cert_id}/upload'
        payload = {
            'certificate': certificate,
            'certificate_key': certificate_key,
            'intermediate_certificate': intermediate_certificate
        }
        return self.req('POST', url, payload=payload)

    def download_cert(self, domain: str):
        certs = self.req_cert_list()
        filter_certs = [cert for cert in certs if domain in cert['domain_names']]
        if not filter_certs:
            raise Exception(f'Not found cert of `{domain}`')
        cert_id = filter_certs[0]['id']
        download_resp = self.req_download_cert(cert_id)
        path = os.path.join(self.temp_dir.name, f'{domain}_{time.time()}_{secrets.token_hex(2)}.zip')
        with open(path, 'wb') as f:
            f.write(download_resp.content)
        return path


def _load_config():
    with open('config.toml', 'rb') as file:
        data = tomllib.load(file)
    return Config(**data)


class NPMSync:
    def __init__(self, config: Config):
        self.config: Config = config
        self.local_npm_req = NPMRequester(
            self.config.local_url,
            self.config.local_username,
            self.config.local_password,
            self.config
        )
        self.remote_npm_req = NPMRequester(
            self.config.remote_url,
            self.config.remote_username,
            self.config.remote_password,
            self.config
        )

    def run(self):
        # logger.info(f'will sync {len(self.config.sync_domains)} domains: {self.config.sync_domains},'
        #             f' from {self.config.remote_url} to {self.config.local_url}, interval: {self.config.interval}s')
        logger.info(f'sync from {self.config.remote_url} to {self.config.local_url}')
        if not self.config.sync_domains:
            return
        remote_certs = self.remote_npm_req.req_cert_list()
        local_certs = self.local_npm_req.req_cert_list()
        failed = []
        for domain in self.config.sync_domains:
            try:
                remote_filter_certs = [cert for cert in remote_certs if domain in cert['domain_names']]
                if not remote_filter_certs:
                    raise Exception('Not found remote cert.')
                remote_cert_id = remote_filter_certs[0]['id']
                remote_cert_info = self.remote_npm_req.req_cert_info(remote_cert_id)

                local_filter_certs = [cert for cert in local_certs if domain in cert['domain_names']]
                if local_filter_certs:
                    local_cert_id = local_filter_certs[0]['id']
                    local_cert_info = self.local_npm_req.req_cert_info(local_cert_id)
                    if local_cert_info['meta'] == remote_cert_info['meta']:
                        logger.debug(f'[{domain}] local is the same as remote, skip.')
                        continue
                else:
                    local_cert_id = self.local_npm_req.req_add_cert(domain)['id']
                logger.info(f'[{domain}] sync from remote.')
                self.local_npm_req.req_upload_cert(local_cert_id, **remote_cert_info['meta'])
            except Exception as e:
                msg = f'[{domain}] sync failed: {e}'
                failed.append(msg)
                logger.error(msg)
        if failed:
            raise Exception('; '.join(failed))


if __name__ == '__main__':
    syncer = NPMSync(_load_config())
    syncer.run()
