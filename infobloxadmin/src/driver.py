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

    def create_host_record(self, context, dns_name, ip_address, network_address, mac_address, exclude_range):
        """
        :param ResourceCommandContext context:
        :param str ip_address:
        :param str network_address:
        :param str dns_name:
        :param str mac_address:
        :param str exclude_range:
        :return:
        """
        headers = {"ContentType": "application/json", "Accept": "*/*"}
        api_version = "v2.5"
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")
        infoblox_address = context.resource.address
        infoblox_url = f"https://{infoblox_address}/wapi/{api_version}/record:host"
        infoblox_username = context.resource.attributes.get(f"{context.resource.model}.User")
        infoblox_password = cs_api.DecryptPassword(context.resource.attributes.get(
            f"{context.resource.model}.Password")).Value
        infoblox_view = context.resource.attributes.get(f"{context.resource.model}.View")
        infoblox_domain_suffix = context.resource.attributes.get(f"{context.resource.model}.DomainSuffix")
        if not infoblox_domain_suffix.startswith("."):
            infoblox_domain_suffix = "." + infoblox_domain_suffix
        request_body = {}
        if not dns_name.endswith(infoblox_domain_suffix):
            dns_name = dns_name + infoblox_domain_suffix
        request_body["name"] = dns_name
        if ip_address:
            request_body["ipv4addrs"] = [{"ipv4addr": ip_address}]
        elif network_address:
            # request_body["ipv4addrs"] = [{"ipv4addr": f"func:nextavailableip:{network_address}"}]
            request_body["ipv4addrs"] = [{"ipv4addr": {"_object_function": "next_available_ip",
                                                       "_object": "network",
                                                       "_object_parameters": {"network": network_address},
                                                       "_parameters": {"num": 1},
                                                       "_result_field": "ips"}}]
            if exclude_range:
                request_body["ipv4addrs"][0]["ipv4addr"]["_parameters"]["exclude"] = exclude_range.split(",")
        else:
            raise Exception("'IP Address' or 'Network Address' must be supplied")
        request_body["ipv4addrs"][0]["view"] = infoblox_view

        if mac_address:
            request_body["ipv4addrs"][0]["mac"] = mac_address
            request_body["ipv4addrs"][0]["configure_for_dhcp"] = True
        try:
            cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id, f"Request:\n{request_body}")
            result = requests.post(infoblox_url, headers=headers, json=request_body,
                                   auth=HTTPBasicAuth(infoblox_username, infoblox_password), verify=False)
            content = result.content.decode()
            if result.status_code > 299:
                raise Exception(f"InfoBlox returned error code: '{result.status_code}', content: '{content}'")
            else:
                cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id,
                                                       f"InfoBlox configured.\nResult:\n{content}")
        except Exception as e:
            raise Exception(f"Error sending request to InfoBlox. Error: {e}")

    def get_host_record_by_name(self, context, dns_name):
        """
        :param ResourceCommandContext context:
        :param str dns_name:
        :return:
        """
        headers = {"ContentType": "application/json", "Accept": "*/*"}
        api_version = "v2.5"
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")
        infoblox_address = context.resource.address
        infoblox_url = f"https://{infoblox_address}/wapi/{api_version}/record:host?name~={dns_name}"
        infoblox_username = context.resource.attributes.get(f"{context.resource.model}.User")
        infoblox_password = cs_api.DecryptPassword(context.resource.attributes.get(
            f"{context.resource.model}.Password")).Value
        try:
            cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id, f"Request:\n{infoblox_url}")
            result = requests.get(infoblox_url, headers=headers, auth=HTTPBasicAuth(infoblox_username,
                                                                                    infoblox_password), verify=False)
            content = result.content.decode()
            if result.status_code > 299:
                raise Exception(f"InfoBlox returned error code: '{result.status_code}', content: '{content}'")
            else:
                cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id,
                                                       f"InfoBlox configured.\nResult:\n{content}")
        except Exception as e:
            raise Exception(f"Error sending request to InfoBlox. Error: {e}")

