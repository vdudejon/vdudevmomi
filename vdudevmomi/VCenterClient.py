import atexit
import base64
import logging
import os
import ssl
import sys
from typing import Union

import requests
from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim, vmodl


class VCenterException(Exception):
    """Overrides the base Exception raised with this name"""

    def __init__(self, message):
        super().__init__(f"VCenterException: {message}")


class VCenterClient:
    """
    A class for managing connections and operations with VMware vCenter servers.
    This class provides methods to establish and manage connections to vCenter servers,
    retrieve information about virtual machines, clusters, and more.
    Attributes:
        vc_name (str): The hostname or IP address of the vCenter server.
        vc_user (str): The username for authenticating with the vCenter server.
        vc_pass (str): The password for authenticating with the vCenter server.
        vc_status (str): The connection status ('Connected' if connected, otherwise '').
        service_instance (vim.ServiceInstance): The vCenter service instance object.
    Methods:
        connect_vc(vc_user: str, vc_pass: str) -> Tuple[str, vim.ServiceInstance]:
            Establishes a connection to the vCenter server.
        disconnect_vc():
            Disconnects from the vCenter server.
        create_vc_base64_string() -> str:
            Creates a base64 string for connecting to the vCenter REST API.
        get_all_vms() -> Dict[str, vim.VirtualMachine]:
            Returns a dictionary containing all VMware virtual machine objects indexed by name.
        def get_objects_and_properties(obj_type: vim.ManagedEntity,properties: list[str],) -> dict
            Given an object type and a list of properties, returns the objects and those properties as a dictionary
            Highly efficient
        get_vm_by_name(vm_name) -> vim.VirtualMachine:
            Gets a virtual machine by name.
        get_parent_vmhost(vim_vm: vim.VirtualMachine) -> vim.HostSystem:
            Returns the parent host system of a virtual machine.
        get_parent_cluster(vim_object: Union[vim.HostSystem, vim.VirtualMachine]) -> vim.ClusterComputeResource:
            Returns the cluster object for a virtual machine or host system.
        def get_datacenter(vim_object: Union[vim.HostSystem, vim.VirtualMachine, vim.Folder]) -> str:
            Return the datacenter an object belongs to
        get_vm_by_uuid(uuid: str):
            Returns a VM based on its UUID
        get_vm_datastore(virtual_machine: vim.VirtualMachine) -> str:
            A function to return the datastore a given VM resides on.  Returns only the 1st datastore
        get_vm_folder(vim_vm: vim.VirtualMachine) -> vim.Folder:
            Returns the parent folder object of a virtual machine.
        get_vm_folder_path(vim_vm: vim.VirtualMachine) -> str:
            Returns the folder path of a virtual machine.
        get_vmhost_by_uuid(self, uuid: str) -> vim.HostSystem:
            Gets an ESXi Host by UUID
        FindTargetDCPath(vm):
            Finds the top-level datacenter object for a target cluster.
    """

    def __init__(self, vc_name: str):
        self.vc_name: str = vc_name
        self.vc_user: str = ""
        self.vc_pass: str = ""
        self.vc_status: str = ""
        self.service_instance: vim.ServiceInstance = None
        self.logger = logging.getLogger()

        log_format = "%(asctime)s | %(name)s | %(levelname)s | %(filename)s | %(funcName)s:%(lineno)d | %(message)s"
        logging.basicConfig(
            level=os.environ.get("LOGLEVEL", "DEBUG"),
            format=log_format,
            handlers=[logging.StreamHandler(sys.stdout)],
            force=True,
        )

    def connect_vc(self, vc_user: str, vc_pass: str) -> tuple[str, vim.ServiceInstance]:
        """Establishes a connection to the vCenter server"""
        self.vc_user = vc_user
        self.vc_pass = vc_pass

        # Set the SSL context to ignore unverified SSL certs
        # ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        self.logger.debug("attempting connection to vcenter %s", self.vc_name)
        try:
            # Connect to vCenter and set self.service_instance
            self.service_instance = SmartConnect(
                host=self.vc_name, user=vc_user, pwd=vc_pass, sslContext=ssl_context
            )

            # Register disconnect_vc at exit so the connection is cleaned up automatically
            atexit.register(self.disconnect_vc)

            self.logger.info("valid connection to vcenter %s", self.vc_name)
            self.logger.debug("returning vcenter object for %s", self.vc_name)

            # Set self.vc_status and return outputs
            self.vc_status = "Connected"
            return self.vc_status, self.service_instance

        # Raise exception if connection failes
        except Exception as exc:
            self.logger.error("unable to connect to vcenter %s", self.vc_name)
            raise VCenterException(
                "Unable to authenticate. Please check instance and authorization"
            ) from exc

    def disconnect_vc(self):
        """Disconnect from vCenter with additional logging"""

        self.logger.debug("attempting to disconnect from vcenter %s", self.vc_name)
        try:
            Disconnect(self.service_instance)
            self.logger.info("disconnected from vcenter %s", self.vc_name)
        except Exception:
            self.logger.error("unable to disconnect from vcenter %s", self.vc_name)

    def create_vc_base64_string(self) -> str:
        """Creates a base64 string for connecting to vCenter REST API"""

        base_str = f"{self.vc_user}:{self.vc_pass}"
        base_str_bytes = base_str.encode("ascii")
        base64_bytes = base64.b64encode(base_str_bytes)
        base64_string = base64_bytes.decode("ascii")

        return base64_string

    def get_all_vms(self) -> dict[str, vim.VirtualMachine]:
        """Returns a dict containing all vim vm objects indexed by name"""

        self.logger.debug("retrieving all vm content for VCENTER %s", self.vc_name)

        # Create a container view of all VMs
        vm_view = self.service_instance.content.viewManager.CreateContainerView(
            self.service_instance.content.rootFolder, [vim.VirtualMachine], True
        )

        # Create a dict of all VMs indexed by name
        all_vm_info = {}
        for vim_vm in vm_view.view:
            try:
                all_vm_info[vim_vm.name] = {}
                all_vm_info[vim_vm.name]["VM"] = vim_vm
            except Exception:
                self.logger.error("VM not found in VCENTER %s", self.vc_name)

        # Return the dict
        return all_vm_info

    def get_vm_by_name(self, vm_name) -> vim.VirtualMachine:
        """Get VM by name, connecting to vCenter API directly then looking up via UUID"""

        # Build headers and send Rest API Calls to get MOREF
        base64_string = self.create_vc_base64_string()
        headers = {"Authorization": f"Basic {base64_string}"}

        try:
            auth_response = requests.post(
                f"https://{self.vc_name}/api/session",
                headers=headers,
                verify=False,
                timeout=30,
            )
            vc_session_id = auth_response.json()
        except Exception as exc:
            self.logger.error(exc)

        # Get the VM by name and build reusable headers
        vm_url = f"https://{self.vc_name}/api/vcenter/vm?names={vm_name}"
        headers = {"vmware-api-session-id": vc_session_id}
        try:
            rest_vm = requests.get(vm_url, headers=headers, verify=False, timeout=30)
        except Exception as exc:
            self.logger.error(exc)

        # REST API Calls to get UUID by MOREF
        vm_json = rest_vm.json()[0]["vm"]
        vm_uuid_url = f"https://{self.vc_name}/api/vcenter/vm/{vm_json}"
        try:
            vm_uuid = requests.get(
                vm_uuid_url, headers=headers, verify=False, timeout=30
            )
            uuid = vm_uuid.json()["identity"]["instance_uuid"]
        except Exception as exc:
            self.logger.error(exc)

        # Use PYVMOMI to find VM by UUID
        search_index = self.service_instance.content.searchIndex
        vim_vm = search_index.FindByUuid(None, uuid, True, True)

        return vim_vm

    def get_parent_vmhost(self, vim_vm: vim.VirtualMachine) -> vim.HostSystem:
        """Returns the parent vmhost of a VM"""

        self.logger.debug("finding vmhost object for VM %s", vim_vm.name)
        vm_host = vim_vm.summary.runtime.host
        self.logger.debug(
            "returning vmhost object %s for VM %s", vm_host.name, vim_vm.name
        )

        return vm_host

    def get_parent_cluster(
        self, vim_object: Union[vim.HostSystem, vim.VirtualMachine]
    ) -> vim.ClusterComputeResource:
        """Returns the cluster object for a VM or Host"""

        # If the object is a VM, find the host first
        if isinstance(vim_object, vim.VirtualMachine):
            vmhost = self.get_parent_vmhost(vim_object)
        elif isinstance(vim_object, vim.HostSystem):
            vmhost = vim_object
        else:
            raise ValueError("Unsupported object type")

        # Find the cluster
        self.logger.debug("finding cluster object for %s", vim_object.name)
        cluster = vmhost.parent
        try:
            if isinstance(cluster, vim.ClusterComputeResource):
                self.logger.debug(
                    "returning cluster object %s for object %s",
                    cluster.name,
                    vim_object.name,
                )
                return cluster
        except ValueError as exc:
            self.logger.error(str(exc))

        return None

    def get_datacenter(
        self, vim_object: Union[vim.HostSystem, vim.VirtualMachine, vim.Folder]
    ) -> str:
        """A function to return the datacenter an object belongs to"""
        # Retrieve the VM's parent folder
        vm_folder = vim_object.parent

        # Check if the parent folder is the root folder (indicating it's a top-level VM)
        if isinstance(vm_folder, vim.Datacenter):
            return vm_folder.name  # The VM belongs to this datacenter

        # If the parent folder is not a datacenter, recursively check its parent
        elif isinstance(vm_folder, vim.Folder):
            return self.get_datacenter(vm_folder)

        # If the VM's parent is neither a datacenter nor a folder, it may not be in a vCenter
        return "Datacenter not found"  # VM may not belong to a datacenter

    def get_vm_by_uuid(self, uuid: str):
        """Returns a VM based on its UUID"""
        self.logger.debug("Searching for virtual machine with UUID %s", uuid)
        try:
            search_index = self.service_instance.content.searchIndex
            vm = search_index.FindByUuid(None, uuid, True)
            if vm:
                self.logger.debug(
                    "Returning virtual machine %s with UUID %s", vm.name, uuid
                )
                return vm
        except:
            self.logger.error("Could not find virtual machine %s", uuid)

    def get_vm_datastore(self, virtual_machine: vim.VirtualMachine) -> str:
        """
        A function to return the datastore a given VM resides on
        This is lazy and cheap, and returns only the 1st datastore
        """
        datastore = "Datastore not found"
        datastore_url = virtual_machine.config.datastoreUrl
        if datastore_url:
            if datastore_url[0].name:
                datastore = datastore_url[0].name
        return datastore

    def get_vm_folder(self, vim_vm: vim.VirtualMachine) -> vim.ManagedEntity:
        """Returns the parent folder object of a vim.VirtualMachine"""

        self.logger.debug("finding folder object for VM %s", vim_vm.name)
        vm_folder = vim_vm.parent
        try:
            if isinstance(vm_folder, vim.Folder):
                self.logger.debug(
                    "returning folder object %s for VM %s",
                    vm_folder.name,
                    vim_vm.name,
                )
                return vm_folder
        except ValueError as exc:
            self.logger.error(str(exc))

        return vm_folder

    def get_vm_folder_path(self, vim_vm: vim.VirtualMachine) -> str:
        """Return the folder path of a vim.VirtualMachine object"""

        self.logger.debug("Finding folder path for VM %s", vim_vm.name)
        folder_paths = []

        # Traverse the parent hierarchy to collect folder names
        current_object = vim_vm
        while hasattr(current_object, "parent"):
            parent_object = current_object.parent
            if isinstance(parent_object, vim.Folder):
                folder_paths.append(parent_object.name)
            current_object = parent_object

        folder_paths.reverse()
        if not folder_paths:
            self.logger.warning(
                "VM %s is in the root path and not in a folder", vim_vm.name
            )
        # Create a string of the folder paths
        folder_path_str = "/" + "/".join(folder_paths)
        self.logger.debug(
            "Returning folder path %s for VM %s", folder_path_str, vim_vm.name
        )
        return folder_path_str

    def get_vmhost_by_uuid(self, uuid: str) -> vim.HostSystem:
        """Get vim.HostSystem by UUID"""

        try:
            search_index = self.service_instance.content.searchIndex
            vmhost = search_index.FindByUuid(None, uuid, False)
            if vmhost:
                return vmhost
        except:
            logging.error(f"Could not find host {uuid}")
            pass

    def get_objects_and_properties(
        self,
        obj_type: vim.ManagedEntity,
        properties: list[str],
    ) -> dict:
        """
        Fetch properties for specific vSphere objects.
        Parameters:
        - obj_type: Type of the vSphere object
        - properties: List of properties to fetch, ie:
            properties = ["name","summary.runtime.host"]
        Returns:
        - Dictionary of vSphere objects with their properties
        """
        content = self.service_instance.RetrieveContent()
        view = content.viewManager.CreateContainerView(
            container=content.rootFolder, type=[obj_type], recursive=True
        )

        if ("customValue" in properties) or ("summary.customValue" in properties):
            allCustomAttributesNames = {}

            if content.customFieldsManager and content.customFieldsManager.field:
                allCustomAttributesNames.update(
                    dict(
                        [
                            (f.key, f.name)
                            for f in content.customFieldsManager.field
                            if f.managedObjectType in (obj_type, None)
                        ]
                    )
                )

        try:
            PropertyCollector = vmodl.query.PropertyCollector

            # Describe the list of properties we want to fetch for obj_type
            property_spec = PropertyCollector.PropertySpec()
            property_spec.type = obj_type
            property_spec.pathSet = properties

            # Describe where we want to look for obj_type
            traversal_spec = PropertyCollector.TraversalSpec()
            traversal_spec.name = "traverseEntities"
            traversal_spec.path = "view"
            traversal_spec.skip = False
            traversal_spec.type = view.__class__

            # Set the object spec
            obj_spec = PropertyCollector.ObjectSpec()
            obj_spec.obj = view
            obj_spec.skip = True
            obj_spec.selectSet = [traversal_spec]

            # Combine object and property specs into a filter spec
            filter_spec = PropertyCollector.FilterSpec()
            filter_spec.objectSet = [obj_spec]
            filter_spec.propSet = [property_spec]

            retrieved_objects = content.propertyCollector.RetrieveContents(
                [filter_spec]
            )

            # Process retrieved objects into a dictionary
            results = {}
            for obj in retrieved_objects:
                properties = {}
                properties["obj"] = obj.obj
                properties["id"] = obj.obj._moId
                for prop in obj.propSet:
                    # store all attributes together in a python dict and translate its name key to name
                    if "customValue" in prop.name:
                        properties[prop.name] = {}

                        if allCustomAttributesNames:
                            properties[prop.name] = dict(
                                [
                                    (
                                        allCustomAttributesNames[attribute.key],
                                        attribute.value,
                                    )
                                    for attribute in prop.val
                                    if attribute.key in allCustomAttributesNames
                                ]
                            )
                    else:
                        properties[prop.name] = prop.val
                results[obj.obj._moId] = properties

        except Exception as e:
            print("An error occurred: %s", e)

        finally:
            view.Destroy()

        return results

    def FindTargetDCPath(self, vm):
        self.logger.debug(
            "finding top level DC object for target cluster %s",
            vm["TARGETCLUSTER"].name,
        )
        tempobj = vm["TARGETCLUSTER"]
        target_cluster_dc_obj_name = (str((tempobj.parent).parent)).strip("'")
        while hasattr(tempobj, "parent"):
            tempobj = tempobj.parent
            if isinstance(tempobj, vim.Folder):
                top_dc_obj = tempobj
        for childobj in top_dc_obj.childEntity:
            if str(childobj).strip("'") == target_cluster_dc_obj_name:
                vm["TARGETDATACENTER"] = childobj
                break
        self.logger.debug(
            "returning target datacenter object %s for VM %s", top_dc_obj, vm["VM_NAME"]
        )
        return vm
