from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.driver_context import InitCommandContext, ResourceCommandContext, AutoLoadResource, \
    AutoLoadAttribute, AutoLoadDetails, CancellationContext
from cloudshell.api.cloudshell_api import CloudShellAPISession
from infoblox_client import objects
from infoblox_client import connector
import jsonpickle
import logging
import io
import sys


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

    def _infoblox_connector(self, context):
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")

        infoblox_address = context.resource.address
        infoblox_username = context.resource.attributes.get(f"{context.resource.model}.User")
        infoblox_password = cs_api.DecryptPassword(context.resource.attributes.get(
            f"{context.resource.model}.Password")).Value

        infoblox_config = {"host": infoblox_address, "username": infoblox_username, "password": infoblox_password,
                           "ssl_verify": False, "wapi_version": "2.5"}
        try:
            cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id,
                                                   f"Connecting to InfoBlox: '{infoblox_address}'")
            connector.LOG.level = 0
            connector.LOG.handlers.append(logging.FileHandler("C:/Temp/Infoblox.log", "a"))
            connector.LOG.info("Log Started")
            infoblox_connector = connector.Connector(infoblox_config)

            return infoblox_connector
        except Exception as e:
            raise Exception(f"Error connecting to InfoBlox. Error: {e}")

    def create_fixed_ip_host_record(self, context, dns_name, ip_address, mac_address, net_view):
        """
        :param ResourceCommandContext context:
        :param str ip_address:
        :param str dns_name:
        :param str mac_address:
        :return:
        """
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")
        infoblox_view = context.resource.attributes.get(f"{context.resource.model}.View")
        infoblox_domain_suffix = context.resource.attributes.get(f"{context.resource.model}.DomainSuffix")
        if not infoblox_domain_suffix.startswith("."):
            infoblox_domain_suffix = "." + infoblox_domain_suffix

        if not dns_name.endswith(infoblox_domain_suffix):
            dns_name = dns_name + infoblox_domain_suffix

        infoblox_conn = self._infoblox_connector(context)
        # ava_ip = objects.IPAllocation.next_available_ip_from_range(net_view, ip_address, ip_address)
        # cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id,
        #                                        f"IP ava: {jsonpickle.dumps(ava_ip)}")
        if mac_address:
            ip = objects.IP.create(ip=ip_address, mac=mac_address, configure_for_dhcp=True)
        else:
            ip = objects.IP.create(ip=ip_address)
        cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id,
                                               f"IP: {jsonpickle.dumps(ip)}")

        data = objects.HostRecord.create(infoblox_conn, name=dns_name, view=infoblox_view, ip=ip)

        return jsonpickle.dumps(data)

    def create_network_ip_host_record(self, context, dns_name, network_address, mac_address):
        """
        :param ResourceCommandContext context:
        :param str network_address:
        :param str dns_name:
        :param str mac_address:
        :return:
        """
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")
        infoblox_view = context.resource.attributes.get(f"{context.resource.model}.View")
        infoblox_domain_suffix = context.resource.attributes.get(f"{context.resource.model}.DomainSuffix")
        if not infoblox_domain_suffix.startswith("."):
            infoblox_domain_suffix = "." + infoblox_domain_suffix

        if not dns_name.endswith(infoblox_domain_suffix):
            dns_name = dns_name + infoblox_domain_suffix

        infoblox_conn = self._infoblox_connector(context)

        ava_ip = objects.IPAllocation.next_available_ip_from_cidr(infoblox_view, network_address)
        cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id, f"IP ava: {jsonpickle.dumps(ava_ip)}")
        if mac_address:
            ip = objects.IP.create(ip=ava_ip, mac=mac_address, configure_for_dhcp=True)
        else:
            ip = objects.IP.create(ip=ava_ip)
        cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id,
                                               f"IP: {jsonpickle.dumps(ip)}")
        data = objects.HostRecord.create(infoblox_conn, name=dns_name, view=infoblox_view, ip=ip,
                                         configure_for_dhcp=True)

        return jsonpickle.dumps(data)

    def get_host_record_by_name(self, context, dns_name):
        """
        :param ResourceCommandContext context:
        :param str dns_name:
        :return:
        """
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")

        infoblox_view = context.resource.attributes.get(f"{context.resource.model}.View")
        infoblox_conn = self._infoblox_connector(context)
        data = objects.HostRecord.search(infoblox_conn, view=infoblox_view, name=dns_name)

        return jsonpickle.dumps(data)

    def get_host_record_by_ip(self, context, ip_address):
        """
        :param ResourceCommandContext context:
        :param str ip_address:
        :return:
        """
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")
        infoblox_view = context.resource.attributes.get(f"{context.resource.model}.View")
        infoblox_conn = self._infoblox_connector(context)
        data = objects.HostRecord.search(infoblox_conn, view=infoblox_view, ip=ip_address)

        return jsonpickle.dumps(data)

    def delete_host_record(self, context, dns_name):
        raise NotImplementedError
