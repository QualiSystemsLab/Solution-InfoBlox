from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.driver_context import InitCommandContext, ResourceCommandContext, AutoLoadResource, \
    AutoLoadAttribute, AutoLoadDetails, CancellationContext
from cloudshell.api.cloudshell_api import CloudShellAPISession
import requests
from requests.auth import HTTPBasicAuth


class InfobloxadminDriver (ResourceDriverInterface):

    def __init__(self):
        """
        ctor must be without arguments, it is created with reflection at run time
        """
        pass

    def initialize(self, context):
        """
        Initialize the driver session, this function is called everytime a new instance of the driver is created
        This is a good place to load and cache the driver configuration, initiate sessions etc.
        :param InitCommandContext context: the context the command runs on
        """
        pass

    def cleanup(self):
        """
        Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files
        """
        pass

    def _infoblox_request(self, context, method, url, body=None):
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")

        headers = {"ContentType": "application/json", "Accept": "*/*"}
        api_version = "v2.5"
        infoblox_address = context.resource.address
        infoblox_username = context.resource.attributes.get(f"{context.resource.model}.User")
        infoblox_password = cs_api.DecryptPassword(context.resource.attributes.get(
            f"{context.resource.model}.Password")).Value
        infoblox_url = f"https://{infoblox_address}/wapi/{api_version}/{url}"
        method = method.lower()
        try:
            cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id, f"URL: '{infoblox_url}'")
            cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id, f"Method: '{method}'")
            cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id, f"Body: '{body}'")
            if method == "get":
                result = requests.get(infoblox_url, headers=headers, auth=HTTPBasicAuth(infoblox_username,
                                                                                        infoblox_password),
                                      verify=False)
            elif method == "post":
                result = requests.post(infoblox_url, headers=headers, json=body,
                                       auth=HTTPBasicAuth(infoblox_username, infoblox_password), verify=False)
            elif method == "put":
                raise NotImplementedError
            elif method == "delete":
                raise NotImplementedError
            else:
                raise Exception(f"Unsupported request function '{method}'")

            content = result.content.decode()
            if result.status_code > 299:
                raise Exception(f"InfoBlox returned error code: '{result.status_code}', content: '{content}'")
            else:
                cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id,
                                                       f"InfoBlox request completed successfully.\nResult:\n{content}")
                return content
        except Exception as e:
            raise Exception(f"Error sending request to InfoBlox. Error: {e}")

    def create_fixed_ip_host_record(self, context, dns_name, ip_address, mac_address):
        """
        :param ResourceCommandContext context:
        :param str ip_address:
        :param str dns_name:
        :param str mac_address:
        :return:
        """
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")
        url = "record:host"
        infoblox_view = context.resource.attributes.get(f"{context.resource.model}.View")
        infoblox_domain_suffix = context.resource.attributes.get(f"{context.resource.model}.DomainSuffix")
        if not infoblox_domain_suffix.startswith("."):
            infoblox_domain_suffix = "." + infoblox_domain_suffix
        request_body = {}
        if not dns_name.endswith(infoblox_domain_suffix):
            dns_name = dns_name + infoblox_domain_suffix
        request_body["name"] = dns_name
        request_body["view"] = infoblox_view
        request_body["ipv4addrs"] = [{"ipv4addr": ip_address}]

        if mac_address:
            request_body["ipv4addrs"][0]["mac"] = mac_address
            request_body["ipv4addrs"][0]["configure_for_dhcp"] = True

        data = self._infoblox_request(context, "post", url, request_body)
        return data

    def create_network_ip_host_record(self, context, dns_name, network_address, mac_address, exclude_range):
        """
        :param ResourceCommandContext context:
        :param str ip_address:
        :param str network_address:
        :param str dns_name:
        :param str mac_address:
        :param str exclude_range:
        :return:
        """
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")
        url = "record:host"
        infoblox_view = context.resource.attributes.get(f"{context.resource.model}.View")
        infoblox_domain_suffix = context.resource.attributes.get(f"{context.resource.model}.DomainSuffix")
        if not infoblox_domain_suffix.startswith("."):
            infoblox_domain_suffix = "." + infoblox_domain_suffix
        request_body = {}
        if not dns_name.endswith(infoblox_domain_suffix):
            dns_name = dns_name + infoblox_domain_suffix
        request_body["name"] = dns_name
        request_body["view"] = infoblox_view

        # request_body["ipv4addrs"] = [{"ipv4addr": f"func:nextavailableip:{network_address}"}]
        request_body["ipv4addrs"] = [{"ipv4addr": {"_object_function": "next_available_ip",
                                                   "_object": "network",
                                                   "_object_parameters": {"network": network_address},
                                                   "_parameters": {"num": 1},
                                                   "_result_field": "ips"}}]
        if exclude_range:
            request_body["ipv4addrs"][0]["ipv4addr"]["_parameters"]["exclude"] = exclude_range.split(",")

        if mac_address:
            request_body["ipv4addrs"][0]["mac"] = mac_address
            request_body["ipv4addrs"][0]["configure_for_dhcp"] = True

        data = self._infoblox_request(context, "post", url, request_body)
        return data

    def get_host_record_by_name(self, context, dns_name):
        """
        :param ResourceCommandContext context:
        :param str dns_name:
        :return:
        """
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")
        url = f"record:host?name~={dns_name}"

        data = self._infoblox_request(context, "get", url)
        return data

    def delete_host_record(self, context, dns_name):
        raise NotImplementedError
