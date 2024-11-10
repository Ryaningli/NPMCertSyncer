import io
import logging
import os
import time
import zipfile
import datetime
import requests
from dataclasses import dataclass, field
import tomllib
from typing import overload, Literal, Optional

logger = logging.getLogger()

logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
ENV = os.getenv('ENV')  # prod or dev


@dataclass
class Config:
    local_url: str
    local_username: str
    local_password: str

    remote_url: str
    remote_username: str
    remote_password: str

    logger_level: str = logging.INFO
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

    def req_download_cert(self, cert_id: int) -> requests.Response:
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
        files = {
            'certificate': certificate,
            'certificate_key': certificate_key,
            'intermediate_certificate': intermediate_certificate
        }
        return self.req('POST', url, files=files)

    def get_letsencrypt_cert_meta(self, cert_id: int) -> dict[str, str]:
        resp = self.req_download_cert(cert_id)
        zip_file_like = io.BytesIO(resp.content)
        meta = {}
        keys = {
            'cert1.pem': 'certificate',
            'privkey1.pem': 'certificate_key',
            'chain1.pem': 'intermediate_certificate',
        }
        with zipfile.ZipFile(zip_file_like, 'r') as zip_ref:
            for file_name in zip_ref.namelist():
                if key := keys.get(file_name):
                    meta[key] = zip_ref.read(file_name).decode('utf-8')
        if set(meta.keys()) != set(keys.values()):
            raise Exception(f'get letsencrypt cert meta failed, got data: {meta}')
        return meta


def load_config():
    config_path = '../config.env.toml' if ENV == 'dev' else '/data/config.toml'
    if not os.path.exists(config_path):
        raise Exception(f'config file not found: {config_path}')
    with open(config_path, 'rb') as file:
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
        if not self.config.sync_domains:
            return
        remote_certs = self.remote_npm_req.req_cert_list()
        local_certs = self.local_npm_req.req_cert_list()
        failed = []
        for domain in self.config.sync_domains:
            try:
                remote_filter_certs = [cert for cert in remote_certs if
                                       cert['provider'] == 'letsencrypt' and domain in cert['domain_names']]
                if not remote_filter_certs:
                    raise Exception('Not found remote letsencrypt cert.')
                remote_cert_id = remote_filter_certs[0]['id']
                remote_cert_meta = self.remote_npm_req.get_letsencrypt_cert_meta(remote_cert_id)

                local_filter_certs = [cert for cert in local_certs if
                                      cert['provider'] == 'other' and cert['nice_name'] == domain]
                if local_filter_certs:
                    local_cert_id = local_filter_certs[0]['id']
                    local_cert_info = self.local_npm_req.req_cert_info(local_cert_id)
                    if local_cert_info['meta'] == remote_cert_meta:
                        logger.info(f'[{domain}] local is the same as remote, skip.')
                        continue
                else:
                    local_cert_id = self.local_npm_req.req_add_cert(domain)['id']
                logger.info(f'[{domain}] sync from remote.')
                self.local_npm_req.req_upload_cert(
                    local_cert_id,
                    certificate=remote_cert_meta['certificate'].encode('utf-8'),
                    certificate_key=remote_cert_meta['certificate_key'].encode('utf-8'),
                    intermediate_certificate=remote_cert_meta['intermediate_certificate'].encode('utf-8')
                )
            except Exception as e:
                msg = f'[{domain}] sync failed: {e}'
                failed.append(msg)
                logger.error(msg)
        if failed:
            raise Exception('; '.join(failed))
        return failed


def main():
    config = load_config()
    logging.basicConfig(format='[%(asctime)s] [%(levelname)s] %(message)s', level=config.logger_level)
    logger.info(f'will sync {len(config.sync_domains)} domains: {config.sync_domains},'
                f' from {config.remote_url} to {config.local_url}, interval: {config.interval}s')
    while True:
        syncer = NPMSync(config)
        try:
            failed = syncer.run()
            if failed:
                raise Exception(f'\n'.join(failed))
        except Exception as e:
            logger.error(f'syncer run failed: {e}')
        logger.info(f'next will run at {datetime.datetime.now() + datetime.timedelta(seconds=config.interval)}')
        time.sleep(config.interval)


if __name__ == '__main__':
    main()
