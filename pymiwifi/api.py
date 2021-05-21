from hashlib import sha1 as encrypt
from random import random
from time import time
from uuid import getnode
from requests import post,get

PUBLIC_KEY = "a2ffa5c9be07488bbb04a3a47d3c5f6a"


def sha1(x: str):
    return encrypt(x.encode()).hexdigest()


def get_mac_address():
    as_hex = f"{getnode():012x}"
    return ":".join(as_hex[i : i + 2] for i in range(0, 12, 2))


def generate_nonce(miwifi_type=0):
    return f"{miwifi_type}_{get_mac_address()}_{int(time())}_{int(random() * 1000)}"


def generate_password_hash(nonce, password):
    return sha1(nonce + sha1(password + PUBLIC_KEY))


class MiWiFi:
    def __init__(self, address, miwifi_type=0):
        if address.endswith("/"):
            address = address[:-1]
        if not "http" in address and not "https" in address:
            address = "http://"+address

        self.address = address
        self.token = None
        self.miwifi_type = miwifi_type

    def login(self, password):
        nonce = generate_nonce(self.miwifi_type)

        try:
            response = post(
            f"{self.address}/cgi-bin/luci/api/xqsystem/login",
            data={
                "username": "admin",
                "logtype": "2",
                "password": generate_password_hash(f"{nonce}", password),
                "nonce": nonce,
            },)
        except:
            error_msg = f"Check if {self.address} is your router login page."
            raise ValueError(error_msg)

        
        if response.status_code == 200:
            text = response.text[0:10]
            if text.startswith("{"):
                js = response.json()
                code = js['code']
                if code==0:
                    self.token = js['token']
                else:
                    msg = js['msg']
                    if msg=="not auth":
                        msg = "You Don't have authority to login or you've entered an incorrect password."

                    raise ValueError(msg)
            else:
                error_msg = f"Check if {self.address} is your router login page."
                raise ValueError(error_msg)

        return response

    def logout(self):
        return get(
            f"{self.address}/cgi-bin/luci/;stok={self.token}/web/logout"
        )

    def get_api_endpoint(self, endpoint):
        return get(
            f"{self.address}/cgi-bin/luci/;stok={self.token}/api/{endpoint}"
        ).json()

    def status(self):
        return self.get_api_endpoint("misystem/status")

    def device_list(self):
        return self.get_api_endpoint("misystem/devicelist")

    def bandwidth_test(self):
        return self.get_api_endpoint("misystem/bandwidth_test")

    def pppoe_status(self):
        return self.get_api_endpoint("xqnetwork/pppoe_status")

    def wifi_detail_all(self):
        return self.get_api_endpoint("xqnetwork/wifi_detail_all")

    def country_code(self):
        return self.get_api_endpoint("xqsystem/country_code")

    def wan_info(self):
        return self.get_api_endpoint("xqsystem/wan_info")

    def check_wan_type(self):
        return self.get_api_endpoint("xqsystem/check_wan_type")
