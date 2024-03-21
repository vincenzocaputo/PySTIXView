from pyvis.network import Network

from IPython.display import HTML

from stix2 import parsing
from pathlib import Path
from stix2.v21 import Bundle
from stix2.v21 import (
                    TLP_AMBER,
                    TLP_GREEN,
                    TLP_RED,
                    TLP_WHITE)
from stix2.v21.common import MarkingDefinition
from stix2.v21.observables import (
                            AutonomousSystem,
                            DomainName,
                            EmailAddress,
                            EmailMessage,
                            File,
                            IPv4Address,
                            IPv6Address,
                            MACAddress,
                            NetworkTraffic,
                            URL,
                            UserAccount)
from stix2.v21.sro import Relationship
from stix2.v21.sdo import (
                        AttackPattern,
                        Campaign,
                        CourseOfAction,
                        Grouping,
                        Identity,
                        Indicator,
                        Infrastructure,
                        IntrusionSet,
                        Location,
                        Malware,
                        MalwareAnalysis,
                        Note,
                        ObservedData,
                        Opinion,
                        Report,
                        ThreatActor,
                        Tool,
                        Vulnerability)
import os
import json
import base64
import warnings
import re


class PySTIXView:
    """Class to create a graph representing STIX objects and relationships

    :param height: Height of the graph section in px
    :param width: Width of the graph section in px
    :param notebook: If True render the graph in a Jupyter Notebook
    :param style: Style of node icons. It can be one of the following \
            square-flat (default)
            square-dark
            square-lite
            noback-flat
            noback-dark
            round-flat
    """

    def __init__(self, height: str, width: str, notebook: bool = False,
                 select_menu: bool = False, filter_menu: bool = False,
                 style: str = 'square-flat'):

        self.__notebook = notebook
        self.__height = height
        self.__width = width
        if notebook:
            self.__network = Network(height, width, directed=True,
                                     notebook=notebook,
                                     select_menu=select_menu,
                                     filter_menu=filter_menu,
                                     cdn_resources='in_line')
        else:
            self.__network = Network(height, width, directed=True,
                                     notebook=notebook,
                                     select_menu=select_menu,
                                     filter_menu=filter_menu)
        self.__icons_path = Path(os.path.dirname(__file__)) / 'icons'

        STYLES = ['square-flat',
                  'square-dark',
                  'square-lite',
                  'noback-dark',
                  'noback-flat',
                  'round-flat']

        if style in STYLES:
            self.__style = style
        else:
            raise ValueError(f"Invalid style. \
                    Select from the following: {', '.join(STYLES)}")

        self.__network.barnes_hut(gravity=-5000,
                                  central_gravity=0,
                                  spring_length=50,
                                  damping=0.9,
                                  overlap=0)
        self.__custom_types = {}

    def __get_stix_object_type(self, object_to_test) -> str:
        """Check if an object is a valid and supported STIX2 object

        :param object_to_test: STIX Object to test
        :return: 'sdo' if the object provided is a valid STIX Domai Object.
            'observable' if the object provided is a valid STIX
            Cyber-Observable Object.
            None if the object provided is not a valid or supported
            STIX object.
        """

        stix_sdo_types = [
            AttackPattern,
            Campaign,
            CourseOfAction,
            Grouping,
            Identity,
            Indicator,
            Infrastructure,
            IntrusionSet,
            Location,
            Malware,
            MalwareAnalysis,
            Note,
            ObservedData,
            Opinion,
            Report,
            ThreatActor,
            Tool,
            Vulnerability
        ]

        stix_observable_types = [
            AutonomousSystem,
            DomainName,
            EmailAddress,
            EmailMessage,
            File,
            IPv4Address,
            IPv6Address,
            MACAddress,
            NetworkTraffic,
            URL,
            UserAccount
        ]

        for type_ in stix_sdo_types:
            if isinstance(object_to_test, type_):
                # STIX Domain Object detected
                return "sdo"

        for type_ in stix_observable_types:
            if isinstance(object_to_test, type_):
                return "observable"

        if isinstance(object_to_test, MarkingDefinition):
            if object_to_test['definition'] == TLP_AMBER['definition']:
                return 'tlp-amber'
            if object_to_test['definition'] == TLP_GREEN['definition']:
                return 'tlp-green'
            if object_to_test['definition'] == TLP_RED['definition']:
                return 'tlp-red'
            if object_to_test['definition'] == TLP_WHITE['definition']:
                return 'tlp-white'

            return "marking-definition"

        return None

    def _add_edge(self, source_node: str,
                  target_node: str,
                  label: str,
                  value: float = 0.4):
        """Add an edge between two nodes

        :param source_node: The id of the source node of the relationship
        :param target_node: The id of the target node of the relationship
        :param label: Edge label
        :param valye: Edge width
        """

        self.__network.add_edge(source_node,
                                target_node,
                                weigth=value,
                                label=label,
                                arrowStrikethrough=False)

    def __image_to_base64(self, image_path: str) -> str:
        """Encode an image to base64

        :param image_path: Local path to the image to convert
        :return: Base64 encoding of the image
        """

        with open(image_path, "rb") as img_file:
            img = img_file.read()
            img_b64 = base64.b64encode(img).decode('utf-8')
            base64_encoded = f"data:image/png;base64,{img_b64}"
            return base64_encoded

    def add_custom_stix_type(self, custom_type: str,
                             node_icon: str = None,
                             label_name: str = 'name',
                             node_color: str = None):
        """Define a custom STIX object type by assigning an icon
         or a color to the node.
         One of icon or a color must be provided.

        :param custom_type: Name of the custom type to define
        :param node_icon: URL or local path to the image to use as node icon
        :param label_name: name of the field to use as node label
        :param color: Color to assign to the node in hex rgb format
        :raises ValueError: If an attempt is made to add a custom type that
             is already defined.
        """

        if custom_type not in self.__custom_types.keys():
            if node_icon:
                if isinstance(node_icon, str):
                    if node_icon.startswith('http'):
                        self.__custom_types[custom_type] = {'image': node_icon}
                    else:
                        b64_icon = self.__image_to_base64(node_icon)
                        self.__custom_types[custom_type] = {'image': b64_icon}
                else:
                    raise TypeError("Provide a valid URL or path to the icon")
            elif node_color:
                if re.match("#[0-9ABCDEF]{6}", node_color):
                    self.__custom_types[custom_type] = {'color': node_color}
                else:
                    raise TypeError("Provide a valid color in hex rgb format")
            self.__custom_types[custom_type]['label_name'] = label_name
        else:
            raise Exception(f"The custom type {custom_type}\
                     is already defined")

    def add_node(self,
                 stix_obj: AttackPattern | Campaign | CourseOfAction |
                 Grouping | Identity | Indicator | Infrastructure |
                 IntrusionSet | Location | Malware | MalwareAnalysis |
                 Note | ObservedData | Opinion | Report | ThreatActor |
                 Tool | Vulnerability | MarkingDefinition | AutonomousSystem |
                 DomainName | EmailAddress | EmailMessage | File |
                 IPv4Address | IPv6Address | MACAddress | NetworkTraffic |
                 URL | UserAccount | str | dict,
                 is_custom: bool = True,
                 node_icon: str = None,
                 color: str = None) -> bool:
        """Add a node to the graph

        :param stix_obj: STIX Object (SDO, Observable or MarkingDefinition
             to add to the graph
        :param is_custom: Set to True to add a custom STIX Object
             (one of node_icon or color must be provided)
        :param node_icon: URLs or local path to the image to use as node icon
        :param color: Color to be assigned to the node in place of the image.
             Hex RGB format is accepted
        :return: True if the node was added correctly
        :raises KeyError: If a custom type does not have any
             image or color for the node
        :raises TypeError: If an invalid STIX Domain Object is provided
        """

        node_img = None
        if isinstance(stix_obj, dict) or isinstance(stix_obj, str):
            stix_obj = parsing.parse(stix_obj, allow_custom=True)
        else:
            if not hasattr(stix_obj, 'type'):
                raise TypeError("Invalid data provided")

        stix_object_type = self.__get_stix_object_type(stix_obj)
        label_name = 'name'
        if not stix_object_type:
            stix_type = stix_obj['type']
            if stix_type in self.__custom_types.keys():
                if 'image' in self.__custom_types[stix_type].keys():
                    node_shape = "image"
                    node_img = self.__custom_types[stix_type]['image']
                elif 'color' in self.__custom_types[stix_type].keys():
                    node_shape = "dot"
                    node_color = self.__custom_types[stix_type]['color']
                else:
                    raise KeyError("No image nor color found the \
                            custom type {stix_type}")
                label_name = self.__custom_types[stix_type]['label_name']
            else:
                warnings.warn(f"STIX Object {stix_type} is not defined")
                icon_path = (self.__icons_path /
                             "custom" /
                             f"{self.__style}.png")
                node_shape = "image"
                node_img = self.__image_to_base64(icon_path)
        else:
            stix_type = stix_obj['type']
            icon_folder = f"{stix_object_type}/{stix_type}"
            icon_filename = f"{self.__style}.png"
            icon_path = self.__icons_path / icon_folder / icon_filename
            if icon_path.exists():
                node_shape = "image"
                node_img = self.__image_to_base64(icon_path)
            else:
                warnings.warn(f"No file found at {icon_path}")
                node_shape = "dot"
                node_color = "#FF0000"

        node_id = stix_obj['id']
        if hasattr(stix_obj, label_name) or label_name in stix_obj.keys():
            node_label = stix_obj[label_name]
        else:
            warnings.warn(f"STIX Object does not \
                    contain the field {label_name}")
            node_label = stix_obj['type']

        if isinstance(stix_obj, dict):
            node_title = json.dumps(stix_obj)
        else:
            node_title = stix_obj.serialize(pretty=True)

        if node_img:
            self.__network.add_node(node_id,
                                    label=node_label,
                                    shape=node_shape,
                                    image=node_img,
                                    title=node_title)
            return True
        else:
            self.__network.add_node(node_id,
                                    label=node_label,
                                    shape=node_shape,
                                    color=node_color,
                                    title=node_title)
            return True

    def add_bundle(self, bundle: Bundle | dict | str) -> bool:
        """Add a Bundle to the graph

        :param bundle: Bundle object to add to the graph.
        :return: True if the object was added successfully
        :raises TypeError: If an invalid Bundle object is provided
        """

        if isinstance(bundle, dict):
            bundle = parsing.dict_to_stix2(bundle, allow_custom=True)
        elif isinstance(bundle, str):
            bundle = parsing.parse(bundle, allow_custom=True)
        elif not isinstance(bundle, Bundle):
            raise TypeError("Invalid data provided")

        for obj in bundle.objects:
            if isinstance(obj, Relationship):
                self.add_relationship(obj)
            else:
                self.add_node(obj)

        # Parse object_refs
        for obj in bundle.objects:
            if hasattr(obj, 'object_refs'):
                for ref in obj['object_refs']:
                    self._add_edge(obj['id'],
                                   ref,
                                   'refers-to')

    def add_relationship(self, relationship: Relationship |
                         str | dict) -> bool:
        """Add a Relationship object to the graph

        :param relationship: STIX Relationship Object to add
        :return: True if the relationship is added successfully
        :raises TypeError: If an invalid Relationship object is provided
        """

        if isinstance(relationship, dict):
            relationship = parsing.dict_to_stix2(relationship,
                                                 allow_custom=True)
        elif isinstance(relationship, str):
            relationship = parsing.parse(relationship, allow_custom=True)
        elif not isinstance(relationship, Relationship):
            raise TypeError("Invalid data provided")
        self._add_edge(relationship.source_ref,
                       relationship.target_ref,
                       relationship.relationship_type)

    def show_graph(self, show_physics_buttons: bool = False,
                   show_node_buttons: bool = False,
                   show_edge_buttons: bool = False,
                   graph_option: str = None) -> str:
        """Generate and return HTML code to render the graph.
        In case of Jupyter Notebook, the graph is rendered
        via IPython.display.HTML.

        :param show_physics_buttons: Set to True to show graph
             physics options menu
        :param show_node_buttons: Set to True to show graph node
             options menu
        :param show_edge_buttons: Set to True to show graph edge
             options menu
        :param graph_option:
        :return: HTML code representin the graph.
             If execute in a Jupyter Notebook,
             an IPython.display.HTML object is returned
        """

        buttons_filter = []
        if show_physics_buttons:
            buttons_filter.append('physics')
        if show_node_buttons:
            buttons_filter.append('nodes')
        if show_edge_buttons:
            buttons_filter.append('edges')

        if buttons_filter:
            self.__network.show_buttons(filter_=buttons_filter)

        name = 'stix-graph.html'
        html_graph = self.__network.generate_html(name)
        if self.__notebook:
            return HTML(html_graph)
        else:
            return html_graph

    def save_graph(self, name, show_physics_buttons: bool = False,
                   show_node_buttons: bool = False,
                   show_edge_buttons: bool = False,
                   graph_option: str = None):
        """Generate and save HTML file containing the graph.

        :param name: Name of the file to save the graph as
        :param show_physics_buttons: Set to True to show graph
             physics options menu
        :param show_node_buttons: Set to True to show graph
             node options menu
        :param show_edge_buttons: Set to True to show graph
             edge options menu
        :param graph_option:
        """
        buttons_filter = []
        if show_physics_buttons:
            buttons_filter.append('physics')
        if show_node_buttons:
            buttons_filter.append('nodes')
        if show_edge_buttons:
            buttons_filter.append('edges')

        if buttons_filter:
            self.__network.show_buttons(filter_=buttons_filter)

        self.__network.write_html(name)

    def to_json(self) -> str:
        """Get graph data in JSON format

        :return: JSON representation of the graph
        """

        return json.dumps(self.__network.get_network_data())
