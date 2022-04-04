from .attckobject import AttckObject
import attr


@attr.s
class AttckDataComponent:

    created_by_ref = attr.ib()
    modified       = attr.ib()
    created        = attr.ib()
    type           = attr.ib()
    id             = attr.ib()
    name           = attr.ib()
    description    = attr.ib()
    x_mitre_version = attr.ib()
    x_mitre_data_source_ref = attr.ib()
    object_marking_refs = attr.ib()


class AttckDataSource(AttckObject):

    """ICS MITRE ATT&CK Data Source object

    A child class of AttckObject

    Creates objects that are categorized as Mitre ATT&CK ICS
    Data Sources

    Example:
       
    Arguments:
        attck_obj (json) -- Takes the raw Mitre ATT&CK Json object
        AttckObject (dict) -- Takes the Mitre ATT&CK Json object as a
                              kwargs values
    """

    __ATTCK_DATASETS = None

    def __init__(self, attck_obj = None, _data_component_filter=None, _ics_attck_obj=None, **kwargs):
        """
        This class represents a Data Source as defined by the
        ICS MITRE ATT&CK framework.

        Keyword Arguments:
            attck_obj {json} -- A ICS MITRE ATT&CK Framework
                                json object (default: {None})
            _ics_attck_obj {json} -- A ICS MITRE ATT&CK Framework 
                                json object. Used for gathering data_components 
                                and data_sources (default: {None})

        Raises:
            GeneratedDatasetException: Raised an exception when unable
                                       to access or process the external
                                       generated dataset.
        """
        super(AttckDataSource, self).__init__(**kwargs)
        self.__attck_obj = attck_obj
        self.__ics_attck_obj = _ics_attck_obj
        self.__data_component_filter = _data_component_filter
        self.id = self._set_id(kwargs)
        self.created_by_ref = self._set_attribute(kwargs, 'created_by_ref')
        self.name = self._set_attribute(kwargs, 'name')
        self.description = self._set_attribute(kwargs, 'description')
        self.external_reference = self._set_reference(kwargs)
        self.created = self._set_attribute(kwargs, 'created')
        self.modified = self._set_attribute(kwargs, 'modified')
        self.stix = self._set_attribute(kwargs, 'id')
        self.type = self._set_attribute(kwargs, 'type')
        self.wiki = self._set_wiki(kwargs)
        self.contributor = self._set_list_items(kwargs, 'x_mitre_contributors')
        self.platforms = self._set_list_items(kwargs, 'x_mitre_platforms')
        self.collection_layers = self._set_list_items(kwargs, 'x_mitre_collection_layers')
        self.data_components = []
        self.__set_data_component_relationship()

    def __set_data_component_relationship(self):
        if not self.data_components:
            for item in self.__attck_obj['objects']:
                if 'type' in item and item.get('type') == 'x-mitre-data-component':
                    if item['x_mitre_data_source_ref'] == self.stix:
                        if self.__data_component_filter:
                            if item['name'] in self.__data_component_filter:
                                self.data_components.append(AttckDataComponent(**item))
                        else:
                            self.data_components.append(AttckDataComponent(**item))

    @property
    def techniques(self):
        """
        Returns all technique objects as a list that are documented as
        related to a data source

        Returns:
            [list] -- A list of related technique objects defined within the
            ICS MITRE ATT&CK Framework
        """
        from .technique import AttckTechnique
        return_list = []
        for item in self.__ics_attck_obj['objects']:
            if 'type' in item:
                if item['type'] == 'attack-pattern' and item.get('x_mitre_data_sources'):
                    data_sources = self._create_data_sources_dict(item['x_mitre_data_sources'])
                    if data_sources.get(self.name):
                        for component in self.data_components:
                            if component.name in data_sources[self.name]:
                                return_list.append(AttckTechnique(attck_obj=self.__ics_attck_obj, _enterprise_attck_obj=self.__attck_obj, **item))
        return return_list
