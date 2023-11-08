import requests
from datetime import datetime, timezone

init_jwt = {
    'url': "",
    'jwt': ""
}

class CredRefresher:
    def convert_timestamp_to_iso8601(timestamp_ms):
        timestamp_s = timestamp_ms / 1000.0
        dt = datetime.fromtimestamp(timestamp_s, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def generate_aws_tokens_jwt():
        HEADERS = {
            'Accept': 'application/json, text/javascript, */*; q=0.01' ,
            'Content-Type': 'application/json',
            'Content-Length': '0',
            'Authorization': f"Bearer {init_jwt['jwt']}",
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.76'
        }
        resp = requests.post(init_jwt['url'], 
                            headers=HEADERS,
                            timeout=10
                            )
        if resp.status_code == 200:
            json_resp = resp.json()
            expiration = CredRefresher.convert_timestamp_to_iso8601(json_resp['expiration'])
            return {
                'access_key': json_resp['accessKeyId'],
                'secret_key': json_resp['secretAccessKey'],
                'token': json_resp['sessionToken'],
                'expiry_time': expiration,
            }
        else:
            return None


    @staticmethod
    def refresh_creds():
        return CredRefresher.generate_aws_tokens_jwt()
