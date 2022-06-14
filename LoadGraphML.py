import networkx as nx
from securicad.langspec import Lang
from securicad.model import Model, scad_serializer
from securicad.model.exceptions import InvalidFieldException, DuplicateAssociationException
import nvdlib

# G = nx.read_graphml("resources/Example.graphml")
G = nx.read_graphml("resources/Example02062022.graphml")
icsLang = Lang("resources/icslang.mar")
apikey = 'XXXX'
limit = 5

model = Model(lang=icsLang)


def read_node_data(node, key):
    return node[1][key]


def read_edge_data(edge, key):
    return edge[2][key]


def read_node_id(node):
    return node[0]


def resolve_field_name(connection_type, param):
    for association in icsLang.associations:
        if association.name == connection_type:
            if param:
                return association.left_field.name
            else:
                return association.right_field.name
    pass


def get_all_relations(node):
    return_relations = []
    for assoc in node._associations:
        for target in node._associations[assoc].targets:
            return_relations.append(target)
    return return_relations


def change_relations(replace_abstract, replace_instance, not_changed_relations=[]):
    from_node = node_mapping[replace_abstract]
    to_node = node_mapping[replace_instance]
    return_relations = []

    # Check if there are relations that need to be conserved
    if len(not_changed_relations) < 1:
        return_relations = get_all_relations(to_node)

    # move all relations from abstract to instance if not in changed relations
    from_relations = get_all_relations(from_node)
    for field in from_relations:
        if field not in not_changed_relations:
            # move relations to to_node
            to_field = field.field.name
            other_field = field.target.field
            try:
                to_node.field(to_field).connect(other_field)
            except DuplicateAssociationException:
                print("Relation already existing:"+str(assoc))

            # remove relation from from_node
            other_target_object = field.association.source_object
            other_target_object_alternative = field.association.target_object
            try:
                from_node.field(to_field).disconnect(other_target_object)
            except:
                from_node.field(to_field).disconnect(other_target_object_alternative)

    return return_relations


def create_instance(simulation, inkrement):
    # replace abstract with concrete
    i = 0
    key_list = list(node_abstract)
    not_changed_relations = []
    
    while i < len(node_abstract):
        replace_abstract = key_list[i]
        replace_instance = simulation[i]
        not_changed_relations.append(change_relations(replace_abstract, replace_instance))
        i += 1        
        
    # save model
    scad_serializer.serialize_model(model, "resources/test"+str(inkrement)+".sCAD")
    print("resources/test"+str(inkrement)+".sCAD saved")
    
    # reverse
    i = 0

    while i < len(node_abstract):
        reverse_abstract = key_list[i]
        reverse_instance = simulation[i]
        change_relations(reverse_instance, reverse_abstract, not_changed_relations[i])
        i += 1
    pass


node_mapping = {}
node_abstract = {}
attacker = {}


def get_vulnerabilities(node_name):
    vulnerabilities = []
    cpes = nvdlib.searchCPE(keyword=node_name, key=apikey, limit=limit)

    for cpe in cpes:
        for vulnerability in nvdlib.searchCVE(cpeName=cpe.cpe23Uri, key=apikey):
            vulnerabilities.append(vulnerability)

    return vulnerabilities


def get_asset(type):
    for asset in icsLang.assets:
        if icsLang.assets[asset].name == type:
            return icsLang.assets[asset]


def in_inheritance_hierarchy(type_to_check, super_type):
    return get_asset(type_to_check).is_sub_type_of(get_asset(super_type))


# map nodes
for node in G.nodes(data=True):
    if read_node_data(node, "type") != "Attacker":
        type = read_node_data(node, "type")
        obj = model.create_object(type, read_node_data(node, 'name'))
        node_mapping.update({read_node_id(node): obj})
        if read_node_data(node, 'abstract'):
            node_abstract.update({read_node_id(node): []})
        elif in_inheritance_hierarchy(type, 'Application') or in_inheritance_hierarchy(type, 'SoftwareProduct'):
            # scan for known vulnerabilities
            for vulnerability in get_vulnerabilities(read_node_data(node, 'name')):
                vuln = model.create_object("SoftwareVulnerability", vulnerability.cve.CVE_data_meta.ID)

                # connect the vulnerability
                if in_inheritance_hierarchy(type, 'Application'):
                    vuln.field('application').connect(obj.field('vulnerabilities'))
                else:
                    vuln.field('softwareProduct').connect(obj.field('softProductVulnerabilities'))

                # cvss V3
                if hasattr(vulnerability.impact, 'baseMetricV3'):
                    # attack vector
                    attackVector = vulnerability.impact.baseMetricV3.cvssV3.attackVector.upper()
                    if attackVector == 'NETWORK':
                        vuln.defense('networkAccessRequired').probability = 1.0
                    elif attackVector == 'ADJACENT':
                        pass  # no equivalent in icsLang
                    elif attackVector == 'LOCAL':
                        vuln.defense('localAccessRequired').probability = 1.0
                    elif attackVector == 'PHYSICAL':
                        vuln.defense('physicalAccessRequired').probability = 1.0

                    # privileges required
                    privilegesRequired = vulnerability.impact.baseMetricV3.cvssV3.privilegesRequired.upper()
                    if privilegesRequired == 'NONE':
                        pass  # do nothing
                    elif privilegesRequired == 'LOW':
                        vuln.defense('lowPrivilegesRequired').probability = 1.0
                    elif privilegesRequired == 'HIGH':
                        vuln.defense('highPrivilegesRequired').probability = 1.0

                    # user interaction required
                    userInteractionRequired = vulnerability.impact.baseMetricV3.cvssV3.userInteraction.upper()
                    if userInteractionRequired == 'NONE':
                        vuln.defense('userInteractionRequired').probability = 0.0
                    elif userInteractionRequired == 'REQUIRED':
                        vuln.defense('userInteractionRequired').probability = 1.0

                    # confidentiality impact
                    confidentialityImpact = vulnerability.impact.baseMetricV3.cvssV3.confidentialityImpact.upper()
                    if confidentialityImpact == 'NONE':
                        vuln.defense('confidentialityImpactLimitations').probability = 1.0
                    elif confidentialityImpact == 'LOW':
                        vuln.defense('confidentialityImpactLimitations').probability = 0.7
                    elif confidentialityImpact == 'HIGH':
                        vuln.defense('confidentialityImpactLimitations').probability = 0.0

                    # INTEGRITY impact
                    integrityImpact = vulnerability.impact.baseMetricV3.cvssV3.integrityImpact.upper()
                    if confidentialityImpact == 'NONE':
                        vuln.defense('integrityImpactLimitations').probability = 1.0
                    elif confidentialityImpact == 'LOW':
                        vuln.defense('integrityImpactLimitations').probability = 0.7
                    elif confidentialityImpact == 'HIGH':
                        vuln.defense('integrityImpactLimitations').probability = 0.0

                    # availability impact
                    availabilityImpact = vulnerability.impact.baseMetricV3.cvssV3.availabilityImpact.upper()
                    if availabilityImpact == 'NONE':
                        vuln.defense('availabilityImpactLimitations').probability = 1.0
                    elif availabilityImpact == 'LOW':
                        vuln.defense('availabilityImpactLimitations').probability = 0.7
                    elif availabilityImpact == 'HIGH':
                        vuln.defense('availabilityImpactLimitations').probability = 0.0

                    # attack complexity
                    attackComplexity = vulnerability.impact.baseMetricV3.cvssV3.attackComplexity.upper()
                    if attackComplexity == 'LOW':
                        vuln.defense('highComplexityExploitRequired').probability = 0.0
                    elif attackComplexity == 'HIGH':
                        vuln.defense('highComplexityExploitRequired').probability = 1.0
                elif hasattr(vulnerability.impact, 'baseMetricV2'):
                    # access vector
                    accessVector = vulnerability.impact.baseMetricV2.cvssV2.accessVector.upper()
                    if accessVector == 'LOCAL':
                        vuln.defense('localAccessRequired').probability = 1.0
                    elif accessVector == 'ADJACENT':
                        pass
                    elif accessVector == 'NETWORK':
                        vuln.defense('networkAccessRequired')

                    # access complexity
                    accessComplexity = vulnerability.impact.baseMetricV2.cvssV2.accessComplexity.upper()
                    if accessComplexity == 'HIGH':
                        vuln.defense('highComplexityExploitRequired').probability = 1.0
                    elif accessComplexity == 'MEDIUM':
                        vuln.defense('highComplexityExploitRequired').probability = 0.5
                    elif accessComplexity == 'LOW':
                        vuln.defense('highComplexityExploitRequired').probability = 0.0

                    # confidentiality impact
                    confidentialityImpact = vulnerability.impact.baseMetricV2.cvssV2.confidentialityImpact.upper()
                    if confidentialityImpact == 'NONE':
                        vuln.defense('confidentialityImpactLimitations').probability = 1.0
                    elif confidentialityImpact == 'PARTIAL':
                        vuln.defense('confidentialityImpactLimitations').probability = 0.7
                    elif confidentialityImpact == 'COMPLETE':
                        vuln.defense('confidentialityImpactLimitations').probability = 0.0

                    # INTEGRITY impact
                    integrityImpact = vulnerability.impact.baseMetricV2.cvssV2.integrityImpact.upper()
                    if confidentialityImpact == 'NONE':
                        vuln.defense('integrityImpactLimitations').probability = 1.0
                    elif confidentialityImpact == 'PARTIAL':
                        vuln.defense('integrityImpactLimitations').probability = 0.7
                    elif confidentialityImpact == 'COMPLETE':
                        vuln.defense('integrityImpactLimitations').probability = 0.0

                    # availability impact
                    availabilityImpact = vulnerability.impact.baseMetricV2.cvssV2.availabilityImpact.upper()
                    if availabilityImpact == 'NONE':
                        vuln.defense('availabilityImpactLimitations').probability = 1.0
                    elif availabilityImpact == 'PARTIAL':
                        vuln.defense('availabilityImpactLimitations').probability = 0.7
                    elif availabilityImpact == 'COMPLETE':
                        vuln.defense('availabilityImpactLimitations').probability = 0.0

                    # user interaction required
                    userInteractionRequired = vulnerability.impact.baseMetricV2.userInteractionRequired
                    if userInteractionRequired:
                        vuln.defense('userInteractionRequired').probability = 1.0
                    else:
                        vuln.defense('userInteractionRequired').probability = 0.0
    else:
        attacker.update({read_node_id(node): model.create_attacker(name=read_node_data(node, 'name'))})

# map edges
for edge in G.edges(data=True):
    connection_type = read_edge_data(edge, 'type')
    source = edge[0]
    sink = edge[1]

    if connection_type == 'Attack':
        for attacker_key in attacker:
            attacker_source = ''
            attacker_sink = ''
            if attacker_key == source:
                attacker_source = attacker_key
                attacker_sink = sink
            elif attacker_key == sink:
                attacker_source = sink
                attacker_sink = source
            if attacker_source != '':
                attack_step = read_edge_data(edge, 'attacksurface')
                attacker[attacker_key].connect(node_mapping[attacker_sink].attack_step(attack_step))
    elif connection_type == 'Realization':
        if source in node_abstract:
            node_abstract[source].append(sink)
        else:
            node_abstract[sink].append(source)
        # nothing further to do
    else:
        source_node = node_mapping[source]
        sink_node = node_mapping[sink]

        left_field = resolve_field_name(connection_type, False)
        right_field = resolve_field_name(connection_type, True)

        try:
            try:
                source_node.field(left_field).connect(sink_node.field(right_field))
            except InvalidFieldException:
                source_node.field(right_field).connect(sink_node.field(left_field))
        except:
            print("Not able to create edge: "+read_edge_data(edge, 'id'))

if len(node_abstract) > 0:
    # prepare simulations
    simulations = []
    for variant in node_abstract[list(node_abstract)[0]]:
        variant_simulation = [variant]
        simulations.append(variant_simulation)
        index = 1
        while index < len(node_abstract):
            for sub_variant in node_abstract[list(node_abstract[index])]:
                variant_simulation.append(sub_variant)
            index += 1

    # create different models
    inkrement = 0
    for simulation in simulations:
        create_instance(simulation, inkrement)
        inkrement += 1
else:
    scad_serializer.serialize_model(model, "resources/test.sCAD")
