.. pyattck documentation master file, created by
   sphinx-quickstart on Wed May 22 16:06:51 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to pyattck's documentation!
===================================

::

    .______   ____    ____  ___   .___________.___________.  ______  __  ___ 
    |   _  \  \   \  /   / /   \  |           |           | /      ||  |/  / 
    |  |_)  |  \   \/   / /  ^  \ `---|  |----`---|  |----`|  ,----'|  '  /  
    |   ___/    \_    _/ /  /_\  \    |  |        |  |     |  |     |    <   
    |  |          |  |  /  _____  \   |  |        |  |     |  `----.|  .  \  
    | _|          |__| /__/     \__\  |__|        |__|      \______||__|\__\ 
                                                                 


    A Python Module to interact with the Mitre ATT&CK Framework

**pyattck** is a light-weight framework for the Mitre ATT&CK Framework.  This package extracts details about Mitre ATT&CK Tactics, Techniques, Actors/Groups, Tools, Malware, and Mitigations provided by Mitre.

************
FEATURES
************

* Retrieve all Tactics, Techniques, Actors, Malware, Tools, and Mitigations independently 
* Every data point has exposed properties that allow the user to retrieve additional data based on relationships:

  * :doc:`class/actor`

    * Tools used by the Actor or Group
    * Malware used by the Actor or Group
    * Techniques this Actor or Group uses

  * :doc:`class/malware`

    * Actor or Group(s) using this malware
    * Techniques this malware is used with

  * :doc:`class/mitigation`

    * Techniques related to a specific set of mitigation suggestions

  * :doc:`class/tactic`

    * Techniques found in a specific Tactic (phase)

  * :doc:`class/technique`

    * Tactics a technique is found in
    * Mitigation suggestions for a given technique
    * Actor or Group(s) identified as using this technique

  * :doc:`class/tools`

    * Techniques that the specified tool is used within
    * Actor or Group(s) using a specified tool


^^^^^^^^^^^^^^
Installation
^^^^^^^^^^^^^^

"""""""""""""""""
OS X & Linux:
"""""""""""""""""

.. code-block:: guess

   pip install pyattck


"""""""""""""""""
Windows:
"""""""""""""""""

.. code-block:: guess

   pip install pyattck


"""""""""""""""""
Usage example
"""""""""""""""""

To use **pyattck** you must instantiate a **Attck** object.  Although you may interact directly with each class, the intended use is through a **Attck** object:

.. code-block:: python
   :linenos:

   from pyattck import Attck

   attack = Attck()


Once you have a `Attck` object you can access all :doc:`class/tactic`, :doc:`class/technique`, :doc:`class/actor`, :doc:`class/malware`, :doc:`class/mitigation`, and :doc:`class/tools` using this object (as well as objects that are related to them).


You can access the following `main` properties on your **Attck** object:

* actor
* malware
* mitigation
* tactic
* technique
* tools

Each of the `main` properties (above) can return a json object of the entire object or you can access each property individually.  An example of this is here:

.. code-block:: python
   :linenos:

   from pyattck import Attck

   attack = Attck()

   # accessing techniques and their properties
   for technique in attack.techniques:
       # this will return the entire json object for this single technique
       print(technique)

       # if you want to return individual properties of this object you call them directly
       print(technique.id)
       print(technique.name)
       print(technique.alias)
       print(technique.description)
       print(technique.stix)
       print(technique.platforms)
       print(technique.permissions)
       print(technique.wiki)
       .....

The following is only a small sample of the available properties on each object and each object type (actor, tactic, malware, etc.) will have different properties that you can access.

Below shows you how you can access each of object types and their properties.  Additionally, you can access related object types associated with this selected object type:

.. code-block:: python
   :linenos:

   from pyattck import Attck

   attack = Attck()

   # accessing actors
   for actor in attack.actors:
       print(actor)
    
       # accessing malware used by an actor or group
       for malware in actor.malwares:
           print(malware)

       # accessing tools used by an actor or group
       for tool in actor.tools:
           print(tool)

       # accessing techniques used by an actor or group
       for technique in actor.techniques:
           print(technique)

   # accessing malware
   for malware in attack.malwares:
       print(malware)

       # accessing actor or groups using this malware
       for actor in malware.actors:
           print(actor)

       # accessing techniques that this malware is used in
       for technique in malware.techniques:
           print(technique)

   # accessing mitigation
   for mitigation in attack.mitigations:
       print(mitigation)

       # accessing techniques related to mitigation recommendations
       for technique in mitigation.techniques:
           print(technique)

   # accessing tactics
   for tactic in attack.tactics:
       print(tactic)

       # accessing techniques related to this tactic
       for technique in tactic.techniques:
           print(technique)

   # accessing techniques
   for technique in attack.techniques:
       print(technique)

       # accessing tactics that this technique belongs to
       for tactic in technique.tactics:
           print(tactic)

       # accessing mitigation recommendations for this technique
       for mitigation in technique.mitigations:
           print(mitigation)

       # accessing actors using this technique
       for actor in technique.actors:
           print(actor)
    

   # accessing tools
   for tool in attack.tools:
       print(tool)

       # accessing techniques this tool is used in
       for technique in tool.techniques:
           print(technique)

       # accessing actor or groups using this tool
       for actor in tool.actors:
           print(actor)


We understand that there are many different open-source projects being released, even on a daily basis but we wanted to provide a straightforward Python package that allowed the user to identify known relationships between all verticals of the Mitre ATT&CK Framework.

If you are unfamiliar with the Mitre ATT&CK Framework, there are a few key components to ensure you have a firm grasp around.  The first is Tactics & Techniques.  When looking at the Mitre ATT&CK Framework, the Tactics are the columns and represent the different phases of an attack.  

.. note::

   The Mitre ATT&CK Framework is NOT an all encompassing/defacto security coverage map - it is rather a FRAMEWORK and other avenues should be considered when assessing your security posture.

Techniques are the rows and categorized underneath specific tactics (columns).  The Techniques are data points within the framework that provides guidance when assessing your security gaps.  Additionally, Techniques (most) contain mitigation guidance but they also contain information about their relationship to tools, malware, even actors/groups that are/have used this technique during recorded attacks.  

This means, if your organization is focused on TTPs (Tactics Techniques and Procedures) used by certain actors/groups then Mitre ATT&CK Framework is perfect for you.  If you are not at this security maturing within your organization, no worries!  The ATT&CK Framework still provides really good guidance in a simple and straightforward layout, but programmatically it is not straightforward--especially if you wanted to measure (or map) your security controls using the framework.


.. toctree::
   :maxdepth: 2
   :caption: Contents:
   
   class/actor
   class/malware
   class/mitigation
   class/tactic
   class/technique
   class/tools


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
