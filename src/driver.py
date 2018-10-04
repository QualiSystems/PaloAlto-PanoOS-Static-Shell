#!/usr/bin/python
# -*- coding: utf-8 -*-

import jsonpickle

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

from cloudshell.cp.vcenter.commands.load_vm import VMLoader
from cloudshell.cp.vcenter.common.cloud_shell.driver_helper import CloudshellDriverHelper
from cloudshell.cp.vcenter.common.model_factory import ResourceModelParser
from cloudshell.cp.vcenter.common.vcenter.vmomi_service import pyVmomiService
from cloudshell.cp.vcenter.common.vcenter.task_waiter import SynchronousTaskWaiter
from cloudshell.cp.vcenter.models.QualiDriverModels import AutoLoadAttribute
from cloudshell.cp.vcenter.vm.ip_manager import VMIPManager
from cloudshell.devices.driver_helper import get_logger_with_thread_id, get_api, get_cli, parse_custom_commands
from cloudshell.devices.standards.firewall.configuration_attributes_structure import \
    create_firewall_resource_from_context
from cloudshell.devices.runners.run_command_runner import RunCommandRunner
from cloudshell.devices.runners.state_runner import StateRunner
from cloudshell.firewall.firewall_resource_driver_interface import FirewallResourceDriverInterface
from cloudshell.firewall.paloalto.panos.cli.panos_cli_handler import PanOSCliHandler as CliHandler
from cloudshell.firewall.paloalto.panos.runners.panos_configuration_runner import PanOSConfigurationRunner \
    as ConfigurationRunner
from cloudshell.firewall.paloalto.panos.runners.panos_firmware_runner import PanOSFirmwareRunner \
    as FirmwareRunner
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.driver_context import AutoLoadDetails, AutoLoadAttribute, AutoLoadResource
from cloudshell.shell.core.driver_context import ApiVmDetails, ApiVmCustomParam
from cloudshell.shell.core.driver_utils import GlobalLock


VCENTER_CONNECTION_PORT = 443


class PaloAltoStaticShellDriver(ResourceDriverInterface, FirewallResourceDriverInterface, GlobalLock):
    SUPPORTED_OS = [r"Palo Alto"]
    SHELL_NAME = "PaloAlto Static vFirewall"
    PORT_MODEL = "GenericVPort"
    DOMAIN = "Global"

    def __init__(self):
        super(PaloAltoStaticShellDriver, self).__init__()
        self._cli = None
        self.cs_helper = CloudshellDriverHelper()
        self.model_parser = ResourceModelParser()
        self.ip_manager = VMIPManager()
        self.task_waiter = SynchronousTaskWaiter()
        self.pv_service = pyVmomiService(SmartConnect, Disconnect, self.task_waiter)

    def initialize(self, context):
        """
        Initialize the driver session, this function is called everytime a new instance of the driver is created
        This is a good place to load and cache the driver configuration, initiate sessions etc.
        """

        resource_config = create_firewall_resource_from_context(shell_name=self.SHELL_NAME,
                                                                supported_os=self.SUPPORTED_OS,
                                                                context=context)

        # session_pool_size = int(resource_config.sessions_concurrency_limit or 1)
        session_pool_size = int(resource_config.sessions_concurrency_limit)
        self._cli = get_cli(session_pool_size)
        return 'Finished initializing'

    def cleanup(self):
        """
        Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files
        """
        pass

    def get_inventory(self, context):
        """ Will locate vm in vcenter and fill its uuid """

        logger = get_logger_with_thread_id(context)
        logger.info("Start Autoload process")

        session = self.cs_helper.get_session(context.connectivity.server_address,
                                             context.connectivity.admin_auth_token,
                                             self.DOMAIN)

        vcenter_vblade = context.resource.attributes["{}.vFirewall vCenter VM".format(self.SHELL_NAME)].replace("\\", "/")
        vcenter_name = context.resource.attributes["{}.vCenter Name".format(self.SHELL_NAME)]

        logger.info("Start AutoLoading VM_Path: {0} on vCenter: {1}".format(vcenter_vblade, vcenter_name))

        vcenter_api_res = session.GetResourceDetails(vcenter_name)
        vcenter_resource = self.model_parser.convert_to_vcenter_model(vcenter_api_res)

        si = None

        try:
            logger.info("Connecting to vCenter ({0})".format(vcenter_api_res.Address))
            si = self._get_connection_to_vcenter(self.pv_service, session, vcenter_resource, vcenter_api_res.Address)

            logger.info("Loading VMs UUID")
            vm_loader = VMLoader(self.pv_service)

            vfw_uuid = vm_loader.load_vm_uuid_by_name(si, vcenter_resource, vcenter_vblade)
            logger.info("PanOS vFirewall VM UUID: {0}".format(vfw_uuid))
            logger.info("Loading the IP of the PanOS vFirewall VM")
            vfw_ip = self._try_get_ip(self.pv_service, si, vfw_uuid, vcenter_resource, logger)
            if vfw_ip:
                session.UpdateResourceAddress(context.resource.name, vfw_ip)
            else:
                raise Exception("Determination of PanOS vFirewall IP address failed."
                                "Please, verify that VM is up and running")

            vm = self.pv_service.get_vm_by_uuid(si, vfw_uuid)

            phys_interfaces = []

            for device in vm.config.hardware.device:
                if isinstance(device, vim.vm.device.VirtualEthernetCard):
                    phys_interfaces.append(device)

            resources = []
            attributes = []
            for port_number, phys_interface in enumerate(phys_interfaces):
                if port_number == 0:  # First interface (port number 0) should be Management
                    continue

                network_adapter_number = phys_interface.deviceInfo.label.lower().strip("network adapter ")
                unique_id = hash(phys_interface.macAddress)

                relative_address = "P{}".format(port_number)

                resources.append(AutoLoadResource(model="{}.{}".format(self.SHELL_NAME, self.PORT_MODEL),
                                                  name="Port {}".format(port_number),
                                                  relative_address=relative_address,
                                                  unique_identifier=unique_id))

                attributes.append(AutoLoadAttribute(attribute_name="{}.{}.MAC Address".format(self.SHELL_NAME,
                                                                                              self.PORT_MODEL),
                                                    attribute_value=phys_interface.macAddress,
                                                    relative_address=relative_address))

                attributes.append(AutoLoadAttribute(attribute_name="{}.{}.Requested vNIC Name".format(self.SHELL_NAME,
                                                                                                      self.PORT_MODEL),
                                                    attribute_value=network_adapter_number,
                                                    relative_address=relative_address))

                attributes.append(AutoLoadAttribute(attribute_name="{}.{}.Logical Name".format(self.SHELL_NAME,
                                                                                               self.PORT_MODEL),
                                                    attribute_value="Interface {}".format(port_number),
                                                    relative_address=relative_address))

            attributes.append(AutoLoadAttribute("",
                                                "VmDetails",
                                                self._get_vm_details(vfw_uuid, vcenter_name)))

            autoload_details = AutoLoadDetails(resources=resources, attributes=attributes)
        except Exception:
            logger.exception("Get inventory command failed")
            raise
        finally:
            if si:
                self.pv_service.disconnect(si)

        return autoload_details

    def _try_get_ip(self, pv_service, si, uuid, vcenter_resource, logger):
        ip = None
        try:
            vm = pv_service.get_vm_by_uuid(si, uuid)
            ip_res = self.ip_manager.get_ip(vm,
                                            vcenter_resource.holding_network,
                                            self.ip_manager.get_ip_match_function(None),
                                            cancellation_context=None,
                                            timeout=None,
                                            logger=logger)
            if ip_res.ip_address:
                ip = ip_res.ip_address
        except Exception:
            logger.debug("Error while trying to load VM({0}) IP".format(uuid), exc_info=True)
        return ip

    @staticmethod
    def _get_vm_details(uuid, vcenter_name):

        vm_details = ApiVmDetails()
        vm_details.UID = uuid
        vm_details.CloudProviderName = vcenter_name
        vm_details.CloudProviderFullName = vcenter_name
        vm_details.VmCustomParams = []
        str_vm_details = jsonpickle.encode(vm_details, unpicklable=False)
        return str_vm_details

    def _get_connection_to_vcenter(self, pv_service, session, vcenter_resource, address):
        password = self._decrypt_password(session, vcenter_resource.password)
        si = pv_service.connect(address,
                                vcenter_resource.user,
                                password,
                                VCENTER_CONNECTION_PORT)
        return si

    @staticmethod
    def _decrypt_password(session, password):
        return session.DecryptPassword(password).Value

    def health_check(self, context):
        """Checks if the device is up and connectable
        :param ResourceCommandContext context: ResourceCommandContext object with all Resource
            Attributes inside
        :return: Success or fail message
        :rtype: str
        """

        logger = get_logger_with_thread_id(context)
        api = get_api(context)

        logger.info("CONTEXT: {}".format(context))
        logger.info("SHELL_NAME: {}".format(self.SHELL_NAME))
        logger.info("SUPPORTED_OS: {}".format(self.SUPPORTED_OS))


        resource_config = create_firewall_resource_from_context(shell_name=self.SHELL_NAME,
                                                                supported_os=self.SUPPORTED_OS,
                                                                context=context)

        logger.info("RESOURCE_CONFIG: {}".format(resource_config.__dict__))

        cli_handler = CliHandler(self._cli, resource_config, logger, api)

        state_operations = StateRunner(logger, api, resource_config, cli_handler)

        return state_operations.health_check()

    def run_custom_command(self, context, custom_command):
        """Send custom command

        :param ResourceCommandContext context: ResourceCommandContext object with all Resource Attributes inside
        :return: result
        :rtype: str
        """

        logger = get_logger_with_thread_id(context)
        api = get_api(context)

        resource_config = create_firewall_resource_from_context(shell_name=self.SHELL_NAME,
                                                                supported_os=self.SUPPORTED_OS,
                                                                context=context)

        cli_handler = CliHandler(self._cli, resource_config, logger, api)

        send_command_operations = RunCommandRunner(logger=logger, cli_handler=cli_handler)
        response = send_command_operations.run_custom_command(parse_custom_commands(command=custom_command))
        return response

    def run_custom_config_command(self, context, custom_command):
        """Send custom command in configuration mode

        :param ResourceCommandContext context: ResourceCommandContext object with all Resource Attributes inside
        :return: result
        :rtype: str
        """

        logger = get_logger_with_thread_id(context)
        api = get_api(context)

        resource_config = create_firewall_resource_from_context(shell_name=self.SHELL_NAME,
                                                                supported_os=self.SUPPORTED_OS,
                                                                context=context)

        cli_handler = CliHandler(self._cli, resource_config, logger, api)

        send_command_operations = RunCommandRunner(logger=logger, cli_handler=cli_handler)
        result_str = send_command_operations.run_custom_config_command(parse_custom_commands(command=custom_command))
        return result_str

    @GlobalLock.lock
    def save(self, context, folder_path, configuration_type):
        """Save a configuration file to the provided destination
        :param ResourceCommandContext context: The context object for the command with resource and
            reservation info
        :param str folder_path: The path to the folder in which the configuration file will be saved
        :param str configuration_type: startup or running config
        :return The configuration file name
        :rtype: str
        """

        logger = get_logger_with_thread_id(context)
        api = get_api(context)

        resource_config = create_firewall_resource_from_context(self.SHELL_NAME, self.SUPPORTED_OS, context)
        cli_handler = CliHandler(self._cli, resource_config, logger, api)

        configuration_type = configuration_type or 'running'

        configuration_operations = ConfigurationRunner(logger, resource_config, api, cli_handler)
        logger.info('Save started')
        response = configuration_operations.save(folder_path, configuration_type)
        logger.info('Save completed')
        return response

    @GlobalLock.lock
    def restore(self, context, path, configuration_type, restore_method):
        """Restores a configuration file
        :param ResourceCommandContext context: The context object for the command with resource and
            reservation info
        :param str path: The path to the configuration file, including the configuration file name
        :param str restore_method: Determines whether the restore should append or override the
            current configuration
        :param str configuration_type: Specify whether the file should update the startup or
            running config
        """

        logger = get_logger_with_thread_id(context)
        api = get_api(context)

        resource_config = create_firewall_resource_from_context(self.SHELL_NAME, self.SUPPORTED_OS, context)
        cli_handler = CliHandler(self._cli, resource_config, logger, api)

        configuration_type = configuration_type or 'running'
        restore_method = restore_method or 'override'

        configuration_operations = ConfigurationRunner(logger, resource_config, api, cli_handler)
        logger.info('Restore started')
        configuration_operations.restore(path, configuration_type, restore_method)
        logger.info('Restore completed')

    def orchestration_save(self, context, mode, custom_params):
        """Saves the Shell state and returns a description of the saved artifacts and information
        This command is intended for API use only by sandbox orchestration scripts to implement
        a save and restore workflow
        :param ResourceCommandContext context: the context object containing resource and
            reservation info
        :param str mode: Snapshot save mode, can be one of two values 'shallow' (default) or 'deep'
        :param str custom_params: Set of custom parameters for the save operation
        :return: SavedResults serialized as JSON
        :rtype: OrchestrationSaveResult
        """

        logger = get_logger_with_thread_id(context)
        api = get_api(context)

        resource_config = create_firewall_resource_from_context(self.SHELL_NAME, self.SUPPORTED_OS, context)
        cli_handler = CliHandler(self._cli, resource_config, logger, api)

        configuration_operations = ConfigurationRunner(logger, resource_config, api, cli_handler)
        logger.info('Orchestration save started')
        response = configuration_operations.orchestration_save(mode, custom_params)
        logger.info('Orchestration save completed')
        return response

    def orchestration_restore(self, context, saved_artifact_info, custom_params):
        """Restores a saved artifact previously saved by this Shell driver using the
            orchestration_save function
        :param ResourceCommandContext context: The context object for the command with resource and
            reservation info
        :param str saved_artifact_info: A JSON string representing the state to restore including
            saved artifacts and info
        :param str custom_params: Set of custom parameters for the restore operation
        """

        logger = get_logger_with_thread_id(context)
        api = get_api(context)

        resource_config = create_firewall_resource_from_context(self.SHELL_NAME, self.SUPPORTED_OS, context)
        cli_handler = CliHandler(self._cli, resource_config, logger, api)

        configuration_operations = ConfigurationRunner(logger, resource_config, api, cli_handler)
        logger.info('Orchestration restore started')
        configuration_operations.orchestration_restore(saved_artifact_info, custom_params)

        logger.info('Orchestration restore completed')

    @GlobalLock.lock
    def load_firmware(self, context, path):
        """Upload and updates firmware on the resource
        :param ResourceCommandContext context: The context object for the command with resource and
            reservation info
        :param str path: path to tftp server where firmware file is stored
        """

        logger = get_logger_with_thread_id(context)
        api = get_api(context)

        resource_config = create_firewall_resource_from_context(self.SHELL_NAME, self.SUPPORTED_OS, context)
        cli_handler = CliHandler(self._cli, resource_config, logger, api)

        logger.info('Start Load Firmware')
        firmware_operations = FirmwareRunner(logger, cli_handler)
        response = firmware_operations.load_firmware(path)

        logger.info('Finish Load Firmware: {}'.format(response))

    def shutdown(self, context):
        """Sends a graceful shutdown to the device
        :param ResourceCommandContext context: The context object for the command with resource and
            reservation info
        """

        logger = get_logger_with_thread_id(context)
        api = get_api(context)

        resource_config = create_firewall_resource_from_context(self.SHELL_NAME, self.SUPPORTED_OS, context)
        cli_handler = CliHandler(self._cli, resource_config, logger, api)

        state_operations = StateRunner(logger, api, resource_config, cli_handler)
        return state_operations.shutdown()
