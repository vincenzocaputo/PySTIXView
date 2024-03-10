Usage
==============

Below is a simple example to create a graph from the STIX2 Bundle `Threat Actor Leveraging Attack Patterns and Malware <https://oasis-open.github.io/cti-documentation/examples/threat-actor-leveraging-attack-patterns-and-malware>`. (The JSON file is available at https://github.com/oasis-open/cti-documentation/blob/main/examples/example_json/threat-actor-leveraging-attack-patterns-and-malware.json)

.. code-block:: python

    from pystixview import PySTIXView

    stix_graph = PySTIXView("600px", "100%")
    with open("threat-actor-leveraging-attack-patterns-and-malware.json", "r") as fd:
        stix_graph.add_bundle(fd.read())
    stix_graph.save_graph("threat-actor-leveraging-attack-patterns-and-malware.html")

PySTIXView can be used also in Jupyter Notebook:

.. image:: https://raw.githubusercontent.com/vincenzocaputo/PySTIXView/main/_media/jupyter_example.png

