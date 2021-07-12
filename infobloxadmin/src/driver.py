from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.driver_context import InitCommandContext, ResourceCommandContext, AutoLoadResource, \
    AutoLoadAttribute, AutoLoadDetails, CancellationContext
from cloudshell.api.cloudshell_api import CloudShellAPISession
from infoblox_client import objects
from infoblox_client import connector
from cloudshell.logging.qs_logger import get_qs_logger


class InfobloxadminDriver (ResourceDriverInterface):
    COMMENT = "Created by Quali CloudShell"

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

    @staticmethod
    def _get_logger(context):
        logger = get_qs_logger(context.reservation.reservation_id)
        logger.setLevel(0)
        return logger

    def _get_host_domain_name(self, context, host_name):
        infoblox_domain_suffix = context.resource.attributes.get(f"{context.resource.model}.DomainSuffix")
        if not infoblox_domain_suffix.startswith("."):
            infoblox_domain_suffix = "." + infoblox_domain_suffix

        if not host_name.endswith(infoblox_domain_suffix):
            host_name = host_name + infoblox_domain_suffix
        return host_name

    def _infoblox_connector(self, context):
        logger = self._get_logger(context)
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")

        infoblox_address = context.resource.address
        infoblox_username = context.resource.attributes.get(f"{context.resource.model}.User")
        infoblox_password = cs_api.DecryptPassword(context.resource.attributes.get(
            f"{context.resource.model}.Password")).Value
        # infoblox version as attribute
        infoblox_config = {"host": infoblox_address, "username": infoblox_username, "password": infoblox_password,
                           "ssl_verify": False, "wapi_version": "2.5"}
        try:
            cs_api.WriteMessageToReservationOutput(context.reservation.reservation_id,
                                                   f"Connecting to InfoBlox: '{infoblox_address}'")
            logger.info(f"Connecting to InfoBlox: '{infoblox_address}'")
            connector.LOG = logger
            infoblox_connector = connector.Connector(infoblox_config)
            return infoblox_connector
        except Exception as e:
            msg = f"Error connecting to infoblox: '{e}'"
            logger.error(msg)
            raise Exception(msg)

    def create_fixed_ip_host_record(self, context, dns_name, ip_address, mac_address):
        """
        :param ResourceCommandContext context:
        :param str ip_address:
        :param str dns_name:
        :param str mac_address:
        :return:
        """
        logger = self._get_logger(context)
        logger.info(f"Creating fixed IP record for Name: '{dns_name}',IP: '{ip_address}',MAC '{mac_address}'")
        infoblox_view = context.resource.attributes.get(f"{context.resource.model}.View")
        dns_name = self._get_host_domain_name(context, dns_name)

        infoblox_conn = self._infoblox_connector(context)
        if mac_address:
            ip = objects.IP.create(ip=ip_address, mac=mac_address, configure_for_dhcp=True)
        else:
            ip = objects.IP.create(ip=ip_address)

        try:
            data = objects.HostRecord.create(infoblox_conn, name=dns_name, view=infoblox_view, ip=ip,
                                             comment=self.COMMENT)
            #logger.info(f"Create Host record info:\n{jsonpickle.dumps(data)}")
            return "Host record created"
        except Exception as e:
            msg = f"Error creating host record with fixed IP. '{e}'"
            logger.error(msg)
            raise

    def create_network_ip_host_record(self, context, dns_name, network_address, mac_address):
        """
        :param ResourceCommandContext context:
        :param str network_address:
        :param str dns_name:
        :param str mac_address:
        :return:
        """
        logger = self._get_logger(context)
        logger.info(f"Creating Network IP record for Name: '{dns_name}',Network: '{network_address}',MAC '{mac_address}'")
        infoblox_view = context.resource.attributes.get(f"{context.resource.model}.View")
        infoblox_network_view = context.resource.attributes.get(f"{context.resource.model}.NetworkView")
        dns_name = self._get_host_domain_name(context, dns_name)

        infoblox_conn = self._infoblox_connector(context)

        ava_ip = objects.IPAllocation.next_available_ip_from_cidr(infoblox_network_view, network_address)
        if mac_address:
            ip = objects.IP.create(ip=ava_ip, mac=mac_address, configure_for_dhcp=True)
        else:
            ip = objects.IP.create(ip=ava_ip)
        try:
            data = objects.HostRecord.create(infoblox_conn, name=dns_name, view=infoblox_view, ip=ip,
                                             configure_for_dhcp=True, comment=self.COMMENT)
            #logger.info(f"Create Host record info:\n{jsonpickle.dumps(data)}")
            return "Host record created"
        except Exception as e:
            msg = f"Error creating host record with network. '{e}'"
            logger.error(msg)
            raise

    def _get_host_record_by_name(self, context, dns_name):
        """
        :param ResourceCommandContext context:
        :param str dns_name:
        :return:
        """
        logger = self._get_logger(context)
        logger.info(f"Getting info for host with Name: '{dns_name}'")
        infoblox_view = context.resource.attributes.get(f"{context.resource.model}.View")
        infoblox_conn = self._infoblox_connector(context)
        dns_name = self._get_host_domain_name(context, dns_name)
        data = objects.HostRecord.search(infoblox_conn, view=infoblox_view, name=dns_name, return_fields=["comment"])
        if not data:
            raise Exception(f"Host record with name '{dns_name}' not found")
        # logger.info(f"Get Host record info:\n{jsonpickle.dumps(data)}")
        return data

    def _get_host_record_by_ip(self, context, ip_address):
        """
        :param ResourceCommandContext context:
        :param str ip_address:
        :return:
        """
        logger = self._get_logger(context)
        logger.info(f"Getting info for host with IP: '{ip_address}'")
        infoblox_view = context.resource.attributes.get(f"{context.resource.model}.View")
        infoblox_conn = self._infoblox_connector(context)
        data = objects.HostRecord.search(infoblox_conn, view=infoblox_view, ip=ip_address)
        if not data:
            raise Exception(f"Host record with IP '{ip_address}' not found")
        # logger.info(f"Get Host record info:\n{jsonpickle.dumps(data)}")
        return data

    def delete_host_record(self, context, dns_name):
        """
        :param ResourceCommandContext context:
        :param str dns_name:
        :return:
        """
        logger = self._get_logger(context)
        logger.info(f"Delete Host record:\n{dns_name}")
        try:
            host_object = self._get_host_record_by_name(context, dns_name)
            logger.info(f"Device '{dns_name}' comment: '{host_object.comment}'")
            if host_object.comment != self.COMMENT:
                logger.error(f"Device '{dns_name}' comment: '{host_object.comment}'")
                raise Exception(f"Unable to delete '{dns_name}' as it was not created by Quali CloudShell")
            host_object.delete()
            msg = f"Host Record deleted:\n{dns_name}"
            logger.info(msg)
            return msg
        except Exception as e:
            logger.error(f"Error deleting host. {e}")
            raise

    def delete_all_records(self, context):
        """
        :param ResourceCommandContext context:
        :return:
        """
        DNS_ATTRIBUTE = "DNS Name"
        logger = self._get_logger(context)
        logger.info("Starting delete all records")
        cs_api = CloudShellAPISession(host=context.connectivity.server_address,
                                      token_id=context.connectivity.admin_auth_token, domain="Global")

        reservation_details = cs_api.GetReservationDetails(context.reservation.reservation_id).ReservationDescription
        for resource in reservation_details.Resources:
            attribute_name = "{}.{}".format(resource.ResourceModelName, DNS_ATTRIBUTE)
            try:
                result = cs_api.GetAttributeValue(resource.Name, attribute_name).Value
                if result:
                    try:
                        self.delete_host_record(context, result)
                    except Exception as e:
                        logger.error(f"Error deleting record for '{result}'. error: {e}")
            except Exception as e:
                logger.info(f"Error getting DNS Attribute '{DNS_ATTRIBUTE}' on resource '{resource.Name}'. Error: {e}")



